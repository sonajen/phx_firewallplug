####################################################################################################
#                                                                                                  #
#  firewall.ex                                                                                     #
#  -----------                                                                                     #
#                                                                                                  #
#  This file defines the PhxFirewallplugWeb.Plugs.Firewall module                                  #
#                                                                                                  #
####################################################################################################

defmodule PhxFirewallplugWeb.Plugs.Firewall do

  require Logger

####################################################################################################
#                                                                                                  #
#  Function : init                                                                                 #
#                                                                                                  #
#  Arguments: opts - the plug options                                                              #
#                                                                                                  #
#  Returned: opts                                                                                  #
#                                                                                                  #
#  Initialize                                                                                      #
#                                                                                                  #
####################################################################################################

  def init(opts) do
    opts
  end

####################################################################################################
#                                                                                                  #
#  Function : call                                                                                 #
#                                                                                                  #
#  Arguments: conn - the connection                                                                #
#             _    - the connection options (unused)                                               #
#                                                                                                  #
#  Returned: the connection                                                                        #
#                                                                                                  #
#  Handle a connection request                                                                     #
#                                                                                                  #
####################################################################################################

  def call(conn,_) do

    # Block IP addresses that do not send GET or HEAD requests. We need to determine which family
    # the IP address belongs to as adding an IPv4 address to the IPv6 set does not block the IPv4
    # address

    with true                       <- conn.method not in [ "GET", "HEAD" ],
         { :ok, strIP, atomFamily } <- getIP(conn)
    do

      # Blacklist the IP address

      if (atomFamily == :inet6),
         do:   System.cmd("/usr/sbin/ipset",[ "add","blacklist_ipv6",strIP ]),
         else: System.cmd("/usr/sbin/ipset",[ "add","blacklist_ipv4",strIP ])

      Logger.warn("BLACKLISTED: #{strIP}: #{conn.host} #{conn.port} #{conn.method} " <>
                               "#{conn.request_path}");

      # Send a HTTP 403 response and halt immediately

      conn
      |> Plug.Conn.put_status(:forbidden)
      |> Plug.Conn.send_resp(403,"Forbidden")
      |> Plug.Conn.halt

    else

      # Allow the request through

      _ -> strIP = :inet.ntoa(conn.remote_ip) |> Kernel.to_string()
           Logger.info("ALLOWED: #{strIP}: #{conn.host} #{conn.port} #{conn.method} #{conn.request_path}");
           conn
    end
  end

####################################################################################################
#                                                                                                  #
#  Function : getIP                                                                                #
#                                                                                                  #
#  Arguments: conn - the connection                                                                #
#                                                                                                  #
#  Returned: { :ok, ip, :inet6 } - a valid IPv6 IP address was found                               #
#            { :ok, ip, :inet }  - a valid IPv4 address was found                                  #
#            :error              - the IP address could not be obtained                            #
#                                                                                                  #
#  Get the remote IP address                                                                       #
#                                                                                                  #
####################################################################################################

  defp getIP(conn) do

    # First try to find an IPv6 address and if that fails check for an IPv4 address

    case getIPv6(conn) do

      { :ok, strIP } -> { :ok, strIP, :inet6 }

      _              -> getIPv4(conn)
    end
  end

####################################################################################################
#                                                                                                  #
#  Function : getIPv6                                                                              #
#                                                                                                  #
#                                                                                                  #
#  Arguments: conn - the connection                                                                #
#                                                                                                  #
#  Returned: { :ok, ip } - a valid IPv6 IP address was found                                       #
#            :error      - the IP address is not in IPv6 format                                    #
#                                                                                                  #
#  Get an IPv6 address from the connection                                                         #
#                                                                                                  #
####################################################################################################

  defp getIPv6(conn) do

    with strIP      <- :inet.ntoa(conn.remote_ip),
         :nomatch   <- :string.find(strIP,'.'),
         { :ok, _ } <- :inet.parse_ipv6_address(strIP)
    do

      { :ok, Kernel.to_string(strIP) }

    else

      _ -> :error
    end
  end

####################################################################################################
#                                                                                                  #
#  Function : getIPv4                                                                              #
#                                                                                                  #
#  Arguments: conn - the connection                                                                #
#                                                                                                  #
#  Returned: { :ok, ip, :inet } - a valid IPv4 IP address was found                                #
#            :error             - the IP address is not in IPv4 format                             #
#                                                                                                  #
#  Get an IPv4 address from the connection                                                         #
#                                                                                                  #
####################################################################################################

  defp getIPv4(conn) do

    with strIP      <- :inet.ntoa(conn.remote_ip) |> :string.split(':',:trailing) |> List.last(),
         { :ok, _ } <- :inet.parse_ipv4_address(strIP)
    do

      { :ok, Kernel.to_string(strIP), :inet }
      
    else

      _ -> :error
    end
  end
end