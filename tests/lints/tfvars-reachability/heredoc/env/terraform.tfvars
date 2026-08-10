feature_enabled = true
policy_body = <<POLICY
undeclared_key_inside_heredoc = "must not be treated as an assignment"
POLICY
comparison_note = "a << b is not a heredoc opener"
