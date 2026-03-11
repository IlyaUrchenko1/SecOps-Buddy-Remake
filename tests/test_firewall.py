from secopsbuddy.responders.firewall import FirewallResponder


def test_private_and_loopback_ips_are_not_blockable_by_default() -> None:
    responder = FirewallResponder(dry_run=True, block_private_ips=False)

    assert responder.is_blockable_ip("192.168.1.10")[0] is False
    assert responder.is_blockable_ip("127.0.0.1")[0] is False
    assert responder.is_blockable_ip("8.8.8.8")[0] is True


def test_block_ips_skips_invalid_and_private_targets() -> None:
    responder = FirewallResponder(dry_run=True, block_private_ips=False)

    actions = responder.block_ips(["", "invalid", "10.10.10.10"])

    assert len(actions) == 3
    assert all(action.blocked is False for action in actions)
    assert all("Пропуск" in action.message for action in actions)
