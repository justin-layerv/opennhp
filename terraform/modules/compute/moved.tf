# State-address migrations for #2628 (take nhp-server private).
#
# These four public-knock-surface resources gained `count =
# var.public_server_surface_enabled ? 1 : 0`. Adding `count` to a previously
# un-indexed resource changes its state address (`x` -> `x[0]`), which Terraform
# would otherwise read as destroy-the-old + create-the-new. These `moved {}` blocks
# rename the existing state in place so:
#   - default (public_server_surface_enabled = true, e.g. prod): `x` -> `x[0]`,
#     config still matches -> NO diff, NO recreation of the live public NLB.
#   - private (public_server_surface_enabled = false, e.g. sandbox at cutover):
#     `x` -> `x[0]`, then count=0 destroys `x[0]` -> a clean single destroy.
#
# moved {} blocks are permanent no-ops once applied; leave them in place.

moved {
  from = aws_lb.server
  to   = aws_lb.server[0]
}

moved {
  from = aws_lb_target_group.udp
  to   = aws_lb_target_group.udp[0]
}

moved {
  from = aws_autoscaling_attachment.server
  to   = aws_autoscaling_attachment.server[0]
}

moved {
  from = aws_lb_listener.udp
  to   = aws_lb_listener.udp[0]
}
