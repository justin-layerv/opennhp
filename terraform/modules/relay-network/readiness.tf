# Keep the one-apply IAM propagation wait on resource DAG roots instead of the
# whole module. Module-level depends_on defers every provider data source, which
# makes endpoint, KMS, Flow Logs, and Resolver policies unknowable in the final
# saved plan exactly when they need the most scrutiny.
resource "terraform_data" "apply_role_ready" {
  input = var.apply_role_ready_token
}
