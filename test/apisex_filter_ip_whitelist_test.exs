defmodule APISexFilterIPBlacklistTest do
  use ExUnit.Case
  use Plug.Test
  doctest APISexFilterIPBlacklist

  test "blacklisted IPv4 address" do
    opts = APISexFilterIPBlacklist.init(blacklist: ["221.92.0.0/16"])

    conn =
      conn(:get, "/")
      |> put_ip_address("221.92.173.24")
      |> APISexFilterIPBlacklist.call(opts)

    assert conn.status == 403
    assert conn.halted
  end

  test "blacklisted IPv4 address, subnet == unique IP address" do
    opts = APISexFilterIPBlacklist.init(blacklist: ["13.4.178.2/32"])

    conn =
      conn(:get, "/")
      |> put_ip_address("13.4.178.2")
      |> APISexFilterIPBlacklist.call(opts)

    assert conn.status == 403
    assert conn.halted
  end

  test "not blacklisted IPv4 address" do
    opts = APISexFilterIPBlacklist.init(blacklist: ["221.92.0.0/16"])

    conn =
      conn(:get, "/")
      |> put_ip_address("17.195.73.12")
      |> APISexFilterIPBlacklist.call(opts)

    refute conn.status == 403
    refute conn.halted
  end

  test "blacklisted IPv6 address" do
    opts = APISexFilterIPBlacklist.init(blacklist: ["2001:F4E5:C0CA:4000::/50"])

    conn =
      conn(:get, "/")
      |> put_ip_address("2001:F4E5:C0CA:4049:D7:912E:FF00:0BD7")
      |> APISexFilterIPBlacklist.call(opts)

    assert conn.status == 403
    assert conn.halted
  end

  test "not blacklisted IPv6 address" do
    opts = APISexFilterIPBlacklist.init(blacklist: ["2001:F4E5:C0CA:4000::/50"])

    conn =
      conn(:get, "/")
      |> put_ip_address("2001:F4E5:C0CA:E049:D7:912E:FF00:0BD7")
      |> APISexFilterIPBlacklist.call(opts)

    refute conn.status == 403
    refute conn.halted
  end

  test "subnet list with blacklisted address" do
    blacklist = [
      "192.168.13.0/24",
      "2001:45B8:991A::/48",
      "23.12.0.0/16",
      "20E7:4128:D4F0:0::/64",
      "91.23.251.0/24"
    ]
    opts = APISexFilterIPBlacklist.init(blacklist: blacklist)

    conn =
      conn(:get, "/")
      |> put_ip_address("20E7:4128:D4F0:0::42")
      |> APISexFilterIPBlacklist.call(opts)

    assert conn.status == 403
    assert conn.halted
  end

  test "subnet list with not blacklisted address" do
    blacklist = [
      "192.168.13.0/24",
      "2001:45B8:991A::/48",
      "23.12.0.0/16",
      "20E7:4128:D4F0:0::/64",
      "91.23.251.0/24"
    ]
    opts = APISexFilterIPBlacklist.init(blacklist: blacklist)

    conn =
      conn(:get, "/")
      |> put_ip_address("8.8.7.8")
      |> APISexFilterIPBlacklist.call(opts)

    refute conn.status == 403
    refute conn.halted
  end

  test "blacklisted IPv4 address with fun callback" do
    opts = APISexFilterIPBlacklist.init(blacklist: &my_cidr_list/1)

    conn =
      conn(:get, "/")
      |> put_ip_address("23.91.178.41")
      |> APISexFilterIPBlacklist.call(opts)

    assert conn.status == 403
    assert conn.halted
  end

  defp put_ip_address(conn, ip_address) do
    %{conn | remote_ip: InetCidr.parse_address!(ip_address)}
  end

  defp my_cidr_list(_) do
    [
      "192.168.0.0/16",
      "23.91.178.32/28"
    ]
  end
end
