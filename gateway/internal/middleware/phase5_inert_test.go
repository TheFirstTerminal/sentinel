package middleware

import "testing"

func TestInertValue(t *testing.T) {
	for _, v := range []string{"name", "product_list_order", "127.0.0.1:8888", "10.0.0.1", "1---", "1YNN",
		"query Q($id: ID!) { node(id: $id) { id name } }"} {
		if !inertValue(v) {
			t.Errorf("%q should not need the model", v)
		}
	}
	for _, v := range []string{"whoami", "id", "PHPINFO", "1--", "1' or 1=1", "name;id", "127.0.0.1;id",
		"127.0.0.1:80/admin", `query { u(n: "x' or 1") { id } }`, "<script>"} {
		if inertValue(v) {
			t.Errorf("%q must still be scored", v)
		}
	}
}
