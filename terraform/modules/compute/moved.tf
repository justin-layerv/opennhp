# Historical #2628 state-address migrations retained for the indexed public edge.
#
# These four public-knock-surface resources previously gained conditional count.
# They now use constant `count = 1` because the assigned-cell public NHP edge is
# invariant. The moved blocks retain indexed state addresses and avoid recreating
# the live public NLB.
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
