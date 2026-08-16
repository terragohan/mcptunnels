// Package tunnelproto defines the shared wire protocol between tunneld and
// tunnel-agent.
//
// An agent dials outbound to ws(s)://<host>/tunnel/connect with headers:
//
//	Authorization: Bearer <agent_key>
//	X-Tenant: <tenant slug>
//	X-Service-Name: <service name>
//
// After the WebSocket upgrade a yamux session runs over the connection:
// tunneld is the yamux client (opens streams), the agent is the yamux server
// (accepts streams). Each yamux stream carries exactly one proxied HTTP
// request/response in standard HTTP/1.1 wire format.
package tunnelproto

const (
	// ConnectPath is the HTTP path agents dial to establish a tunnel.
	ConnectPath = "/tunnel/connect"

	// HeaderTenant carries the tenant slug the agent is registering under.
	HeaderTenant = "X-Tenant"

	// HeaderServiceName carries the service name the agent is registering.
	HeaderServiceName = "X-Service-Name"
)

// AuthorizationHeader builds the Authorization header value for an agent key.
func AuthorizationHeader(agentKey string) string {
	return "Bearer " + agentKey
}
