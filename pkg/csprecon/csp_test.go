package csprecon_test

import (
	"strings"
	"testing"

	"github.com/edoardottt/csprecon/pkg/csprecon"

	"github.com/stretchr/testify/require"
)

func TestParseCSP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty CSP",
			input: "",
			want:  []string{},
		},
		{
			name: "Instagram (https://www.instagram.com/) 2022-12-15",
			input: `report-uri https://www.instagram.com/security/csp_report/; 
				default-src 'self' https://www.instagram.com; 
				img-src data: blob: https://*.fbcdn.net https://*.instagram.com https://*.cdninstagram.com https://*.facebook.com https://*.fbsbx.com https://*.giphy.com;
				font-src data: https://*.fbcdn.net https://*.instagram.com https://*.cdninstagram.com; 
				media-src 'self' blob: https://www.instagram.com https://*.cdninstagram.com https://*.fbcdn.net; 
				manifest-src 'self' https://www.instagram.com; 
				script-src 'self' https://instagram.com https://www.instagram.com https://*.www.instagram.com https://*.cdninstagram.com wss://www.instagram.com https://*.facebook.com https://*.fbcdn.net https://*.facebook.net 'unsafe-inline' 'unsafe-eval' blob:;
				style-src 'self' https://*.www.instagram.com https://www.instagram.com 'unsafe-inline'; 
				connect-src 'self' https://instagram.com https://www.instagram.com https://*.www.instagram.com https://graph.instagram.com https://*.graph.instagram.com https://i.instagram.com/graphql_www https://graphql.instagram.com https://*.cdninstagram.com https://api.instagram.com https://i.instagram.com https://*.i.instagram.com https://*.od.instagram.com wss://www.instagram.com wss://edge-chat.instagram.com https://*.facebook.com https://*.fbcdn.net https://*.facebook.net chrome-extension://boadgeojelhgndaghljhdicfkmllpafd blob:; 
				worker-src 'self' blob: https://www.instagram.com; 
				frame-src 'self' https://instagram.com https://www.instagram.com https://*.instagram.com https://staticxx.facebook.com https://www.facebook.com https://web.facebook.com https://connect.facebook.net https://m.facebook.com https://*.fbsbx.com; 
				object-src 'none'; 
				upgrade-insecure-requests`,
			want: []string{
				"api.instagram.com",
				"*.cdninstagram.com",
				"connect.facebook.net",
				"edge-chat.instagram.com",
				"*.facebook.com",
				"*.facebook.net",
				"*.fbcdn.net",
				"*.fbsbx.com",
				"*.giphy.com",
				"*.graph.instagram.com",
				"graph.instagram.com",
				"graphql.instagram.com",
				"*.i.instagram.com",
				"i.instagram.com",
				"*.instagram.com",
				"instagram.com",
				"m.facebook.com",
				"*.od.instagram.com",
				"staticxx.facebook.com",
				"web.facebook.com",
				"www.facebook.com",
				"*.www.instagram.com",
				"www.instagram.com",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := csprecon.ParseCSP(tt.input, csprecon.CompileRegex(csprecon.DomainRegex))
			require.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestParseBodyCSP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty HTML",
			input: "",
			want:  []string{},
		},
		{
			name: "Instagram (https://www.instagram.com/) 2022-12-15 adapted for HTML meta tag CSP",
			input: `<html>
			<head>
			<meta http-equiv="Content-Security-Policy" content="report-uri https://www.instagram.com/security/csp_report/; 
				default-src 'self' https://www.instagram.com; 
				img-src data: blob: https://*.fbcdn.net https://*.instagram.com https://*.cdninstagram.com https://*.facebook.com https://*.fbsbx.com https://*.giphy.com;
				font-src data: https://*.fbcdn.net https://*.instagram.com https://*.cdninstagram.com; 
				media-src 'self' blob: https://www.instagram.com https://*.cdninstagram.com https://*.fbcdn.net; 
				manifest-src 'self' https://www.instagram.com; 
				script-src 'self' https://instagram.com https://www.instagram.com https://*.www.instagram.com https://*.cdninstagram.com wss://www.instagram.com https://*.facebook.com https://*.fbcdn.net https://*.facebook.net 'unsafe-inline' 'unsafe-eval' blob:;
				style-src 'self' https://*.www.instagram.com https://www.instagram.com 'unsafe-inline'; 
				connect-src 'self' https://instagram.com https://www.instagram.com https://*.www.instagram.com https://graph.instagram.com https://*.graph.instagram.com https://i.instagram.com/graphql_www https://graphql.instagram.com https://*.cdninstagram.com https://api.instagram.com https://i.instagram.com https://*.i.instagram.com https://*.od.instagram.com wss://www.instagram.com wss://edge-chat.instagram.com https://*.facebook.com https://*.fbcdn.net https://*.facebook.net chrome-extension://boadgeojelhgndaghljhdicfkmllpafd blob:; 
				worker-src 'self' blob: https://www.instagram.com; 
				frame-src 'self' https://instagram.com https://www.instagram.com https://*.instagram.com https://staticxx.facebook.com https://www.facebook.com https://web.facebook.com https://connect.facebook.net https://m.facebook.com https://*.fbsbx.com; 
				object-src 'none'; 
				upgrade-insecure-requests"/>
			</head>
			<body>
			</body>
			</html>`,
			want: []string{
				"api.instagram.com",
				"*.cdninstagram.com",
				"connect.facebook.net",
				"edge-chat.instagram.com",
				"*.facebook.com",
				"*.facebook.net",
				"*.fbcdn.net",
				"*.fbsbx.com",
				"*.giphy.com",
				"*.graph.instagram.com",
				"graph.instagram.com",
				"graphql.instagram.com",
				"*.i.instagram.com",
				"i.instagram.com",
				"*.instagram.com",
				"instagram.com",
				"m.facebook.com",
				"*.od.instagram.com",
				"staticxx.facebook.com",
				"web.facebook.com",
				"www.facebook.com",
				"*.www.instagram.com",
				"www.instagram.com",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.NewReader(tt.input)
			got := csprecon.ParseBodyCSP(body, csprecon.CompileRegex(csprecon.DomainRegex))
			require.ElementsMatch(t, tt.want, got)
		})
	}
}
