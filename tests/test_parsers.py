from cyberkit.tool_impl import _parse_nmap_xml_text, _parse_spf_record, _parse_tag_value_record


def test_parse_nmap_xml_text() -> None:
    xml = """
    <nmaprun>
      <host>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="9.0"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    parsed = _parse_nmap_xml_text(xml)
    assert len(parsed["hosts"]) == 1
    assert parsed["hosts"][0]["addresses"][0] == "192.168.1.10"
    assert parsed["hosts"][0]["ports"][0]["port"] == 22
    assert parsed["hosts"][0]["ports"][0]["service"] == "ssh"


def test_parse_spf_record() -> None:
    parsed = _parse_spf_record("v=spf1 include:_spf.example.com ~all")
    assert parsed["has_softfail"] is True
    assert parsed["has_plus_all"] is False
    assert "include:_spf.example.com" in parsed["mechanisms"]


def test_parse_tag_value_record() -> None:
    parsed = _parse_tag_value_record("v=DMARC1; p=quarantine; rua=mailto:d@example.com")
    assert parsed["v"] == "DMARC1"
    assert parsed["p"] == "quarantine"
    assert parsed["rua"] == "mailto:d@example.com"
