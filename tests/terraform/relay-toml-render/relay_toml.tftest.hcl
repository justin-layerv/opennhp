run "actual_template_role_swap" {
  command = plan

  assert {
    condition     = output.old_current == output.new_current
    error_message = "Swapping current/additional relay key roles must be byte-identical in Terraform's actual templatefile renderer."
  }

  assert {
    condition     = length(regexall("(?m)^\\[\\[Relays\\]\\]$", output.old_current)) == 2
    error_message = "The actual relay TOML render must contain exactly two relay peers."
  }

  assert {
    condition     = length(regexall("%\\{|\\$\\{", output.old_current)) == 0
    error_message = "The actual relay TOML render must not retain Terraform template directives."
  }
}
