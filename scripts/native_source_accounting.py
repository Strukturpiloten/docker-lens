"""Pure selected-backend costs for the recovered unadmitted source families.

The canonical harness supplies this selector separately from proof/context data.
These are expectations/reservations only; the existing snapshot owner charges I/O.
"""


def outer_snapshot_cost(outer_backend):
    """Reject absent/noncanonical selectors; never silently select Podman."""
    if type(outer_backend) is str:
        if outer_backend == "podman":
            return 0, 0
        if outer_backend == "docker":
            return 1, 65536
    raise ValueError("invalid source accounting backend")
