// Package promptguard protects AI chat endpoints (apps that pass user text
// to a large language model) from prompt injection: text written to make the
// model ignore its instructions, reveal its hidden prompt, or drop its
// safety rules.
//
// Two layers:
//
//  1. Request check: every text field is normalised (lower case, invisible
//     characters removed, l33t-speak undone, letters squeezed together to
//     beat "i.g.n.o.r.e"-style spacing, base64 decoded) and scored against
//     known injection patterns, like the WAF does for SQL injection.
//  2. Canary check: the app puts a secret marker (canary) in its hidden
//     prompt. If a reply ever contains it, the model was tricked into
//     leaking its prompt, and Sentinel withholds the reply. This catches
//     injections the patterns missed.
package promptguard

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

type Rule struct {
	ID      string
	Name    string
	Score   int
	re      *regexp.Regexp // on normalised text
	compact []string       // phrases matched on letters-only text
}

// Rules: each regex runs on normalised text; compact phrases run on the
// letters-only form, so spacing and punctuation tricks don't help.
var Rules = []Rule{
	{ID: "PI-001", Name: "Instruction override (ignore previous instructions)", Score: 5,
		re:      regexp.MustCompile(`\b(ignore|disregard|forget|skip|override|bypass)\b.{0,30}\b(all|any|every|the|your|my|these|those|previous|prior|above|earlier|preceding|initial|original|system)\b.{0,30}\b(instructions?|rules|prompts?|directions?|guidelines|context|constraints)\b`),
		compact: []string{"ignoreallpreviousinstructions", "ignorepreviousinstructions", "ignoreallinstructions", "disregardpreviousinstructions", "forgetallpreviousinstructions", "ignoreyourinstructions"}},
	{ID: "PI-002", Name: "Asks for the hidden prompt", Score: 5,
		re:      regexp.MustCompile(`\b(reveal|print|show|repeat|output|display|tell me|give me|what (is|are)|dump|leak|recite|copy)\b.{0,40}\b(system prompt|initial prompt|hidden prompt|secret prompt|your (instructions|rules|prompt|guidelines|configuration)|the (instructions|text) above|everything above)\b`),
		compact: []string{"systemprompt", "revealyourinstructions", "printyourinstructions", "showyourinstructions"}},
	{ID: "PI-003", Name: "Jailbreak persona (DAN, developer mode)", Score: 5,
		re:      regexp.MustCompile(`\b(you are now|from now on,? you are|act as|pretend (to be|you are)|roleplay as|enter|enable|switch to)\b.{0,40}\b(dan|jailbr(eak|oken)|developer mode|god mode|unfiltered|unrestricted|uncensored|evil|no (rules|restrictions|limits))\b`),
		compact: []string{"doanythingnow", "developermodeenabled", "jailbreakmode"}},
	{ID: "PI-004", Name: "Fake system or role markers", Score: 4,
		re: regexp.MustCompile(`(<\|?(im_start|im_end|system|endoftext)\|?>|</?system>|\[/?inst\]|^\s*#{2,}\s*(system|instruction)|(^|\n)\s*(system|assistant)\s*:)`)},
	{ID: "PI-005", Name: "New orders for the model", Score: 3,
		re: regexp.MustCompile(`\b(new instructions?|updated instructions?|your new (task|role|goal)|from now on,? (you|your)|instead,? you (will|must|should))\b`)},
	{ID: "PI-006", Name: "Asks to drop safety rules", Score: 3,
		re: regexp.MustCompile(`\b(without|no|ignore|bypass|disable|turn off|remove)\b.{0,20}\b(restrictions?|filters?|limitations?|safety|guardrails?|censorship|content polic(y|ies)|ethic(s|al guidelines))\b`)},
	{ID: "PI-008", Name: "Instruction override in another language", Score: 5,
		re: regexp.MustCompile(`(ignorez|ignore[sz]?|oubliez|ignora|ignoren|olvida|ignoriere|vergiss|игнорируй|забудь|تجاهل|انس|اتجاهل)\S*.{0,40}(instructions|consignes|instrucciones|anweisungen|инструкции|التعليمات|الأوامر|التوجيهات|الاوامر)`)},
	{ID: "PI-009", Name: "Asks for the text before the conversation", Score: 5,
		re: regexp.MustCompile(`\b(everything|all|anything|the (text|words|message|instructions))\b.{0,20}\b(said|written|given|told|stated)?\s*(before|above|prior to|earlier than) (this|my|the first)|\brepeat the (words|text|sentences|lines) above\b|\bstarting with ["'“]?you are\b|\bwhat were you told\b|\b(initial|original|first|system) (instructions?|message|prompt)\b`)},
	{ID: "PI-007", Name: "Data exfiltration link (markdown image to a URL)", Score: 3,
		re: regexp.MustCompile(`!\[[^\]]*\]\(\s*https?://`)},
}

// Match is one rule that fired.
type Match struct {
	RuleID  string `json:"rule_id"`
	Name    string `json:"name"`
	Field   string `json:"field"`
	Excerpt string `json:"excerpt"`
	Via     string `json:"via,omitempty"` // "base64", "letters-only"
}

type Result struct {
	Score   int     `json:"score"`
	Matches []Match `json:"matches"`
}

// Guard scores texts. Threshold is the score at which a text is an attack.
type Guard struct {
	Threshold int
}

// Field is a named piece of user text (a JSON field, a query parameter).
type Field struct{ Name, Text string }

// Inspect scores all fields; each rule counts once per request.
func (g *Guard) Inspect(fields []Field) Result { return g.InspectExcept(fields, nil) }

// InspectExcept is Inspect, but skip(rule, field) can switch a rule off for
// a field (exclusions).
func (g *Guard) InspectExcept(fields []Field, skip func(rule, field string) bool) Result {
	var res Result
	fired := map[string]bool{}
	hit := func(r Rule, f Field, excerpt, via string) {
		if fired[r.ID] || (skip != nil && skip(r.ID, f.Name)) {
			return
		}
		fired[r.ID] = true
		res.Score += r.Score
		res.Matches = append(res.Matches, Match{r.ID, r.Name, f.Name, cut(excerpt, 80), via})
	}
	for _, f := range fields {
		texts := []struct{ text, via string }{{normalise(f.Text), ""}}
		for _, d := range decodeBase64(f.Text) {
			texts = append(texts, struct{ text, via string }{normalise(d), "base64"})
		}
		for _, t := range texts {
			letters := lettersOnly(t.text)
			for _, r := range Rules {
				if r.re != nil {
					if m := r.re.FindString(t.text); m != "" {
						hit(r, f, m, t.via)
						continue
					}
				}
				for _, p := range r.compact {
					if strings.Contains(letters, p) {
						via := "letters-only"
						if t.via != "" {
							via = t.via + ", letters-only"
						}
						hit(r, f, p, via)
						break
					}
				}
			}
		}
	}
	return res
}

func (g *Guard) Attack(r Result) bool { return r.Score >= g.Threshold }

// Fields pulls every string out of a JSON body (or the whole body if it
// isn't JSON).
func Fields(body []byte) []Field {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		if len(body) == 0 {
			return nil
		}
		return []Field{{"body", string(body)}}
	}
	var out []Field
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case string:
			out = append(out, Field{prefix, x})
		case map[string]any:
			for k, vv := range x {
				name := k
				if prefix != "" {
					name = prefix + "." + k
				}
				walk(name, vv)
			}
		case []any:
			for _, vv := range x {
				walk(prefix+"[]", vv)
			}
		}
	}
	walk("", v)
	return out
}

var invisible = strings.NewReplacer(
	"\u200b", "", "\u200c", "", "\u200d", "", "\u2060", "", "\ufeff", "", "\u00ad", "",
)

var leet = strings.NewReplacer("0", "o", "1", "i", "3", "e", "4", "a", "5", "s", "7", "t", "@", "a", "$", "s")

// normalise: lower case, invisible characters removed, look-alike letters
// mapped, l33t-speak undone, whitespace collapsed.
func normalise(s string) string {
	s = invisible.Replace(s)
	var b strings.Builder
	for _, r := range s {
		if m, ok := lookalike[r]; ok {
			r = m
		}
		b.WriteRune(r)
	}
	s = strings.ToLower(b.String())
	s = leetWords(s)
	return strings.Join(strings.Fields(s), " ")
}

// leetWords undoes l33t-speak only inside words that also have letters, so
// ordinary numbers ("2 days") stay as they are.
func leetWords(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		hasLetter, hasDigit := false, false
		for _, r := range w {
			if r >= 'a' && r <= 'z' {
				hasLetter = true
			}
			if strings.ContainsRune("013457@$", r) {
				hasDigit = true
			}
		}
		if hasLetter && hasDigit {
			words[i] = leet.Replace(w)
		}
	}
	return strings.Join(words, " ")
}

// Cyrillic and Greek letters that look like Latin ones.
var lookalike = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
	'А': 'A', 'Е': 'E', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'І': 'I', 'Ѕ': 'S',
	'ο': 'o', 'ν': 'v', 'α': 'a', 'ι': 'i', 'Ι': 'I', 'Ο': 'O',
}

func lettersOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var b64 = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)

// decodeBase64 returns readable text hidden in base64 runs.
func decodeBase64(s string) []string {
	var out []string
	for _, m := range b64.FindAllString(s, 5) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
			d, err := enc.DecodeString(m)
			if err == nil && printable(d) {
				out = append(out, string(d))
				break
			}
		}
	}
	return out
}

func printable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if (c < 32 || c > 126) && c != '\n' && c != '\t' && c != '\r' {
			return false
		}
	}
	return true
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
