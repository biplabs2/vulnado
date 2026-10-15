package com.scalesec.vulnado;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import java.util.ArrayList;
import java.util.List;
import java.io.IOException;
import java.net.*;


public class LinkLister {
  public static List<String> getLinks(String url) throws IOException {
    List<String> result = new ArrayList<String>();
    validatePublicHttpUrl(url);
    // TODO: Use an allowlisted or DNS-pinned fetcher to prevent DNS rebinding.
    Document doc = Jsoup.connect(url).followRedirects(false).get();
    Elements links = doc.select("a");
    for (Element link : links) {
      result.add(link.absUrl("href"));
    }
    return result;
  }

  private static void validatePublicHttpUrl(String value) throws IOException {
    URL url = new URL(value);
    String protocol = url.getProtocol();
    if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
      throw new IOException("Only HTTP and HTTPS URLs are allowed");
    }

    String host = url.getHost();
    if (host.isEmpty()) {
      throw new IOException("URL host is required");
    }

    InetAddress[] addresses = InetAddress.getAllByName(host);
    for (InetAddress address : addresses) {
      if (!isPublicAddress(address)) {
        throw new IOException("Requests to non-public addresses are not allowed");
      }
    }
  }

  private static boolean isPublicAddress(InetAddress address) {
    if (address.isAnyLocalAddress() || address.isLoopbackAddress()
        || address.isLinkLocalAddress() || address.isSiteLocalAddress()
        || address.isMulticastAddress()) {
      return false;
    }

    byte[] bytes = address.getAddress();
    if (address instanceof Inet4Address) {
      int first = bytes[0] & 0xff;
      int second = bytes[1] & 0xff;
      int third = bytes[2] & 0xff;
      return first != 0 && first != 10 && first != 127 && first < 224
          && !(first == 100 && second >= 64 && second <= 127)
          && !(first == 169 && second == 254)
          && !(first == 172 && second >= 16 && second <= 31)
          && !(first == 192 && (second == 0 || second == 168))
          && !(first == 192 && second == 88 && third == 99)
          && !(first == 198 && (second == 18 || second == 19 || second == 51))
          && !(first == 203 && second == 0 && third == 113);
    }

    if (address instanceof Inet6Address) {
      return (bytes[0] & 0xe0) == 0x20
          && !(bytes[0] == 0x20 && bytes[1] == 0x01
              && bytes[2] == 0x0d && bytes[3] == (byte) 0xb8);
    }

    return false;
  }

  public static List<String> getLinksV2(String url) throws BadRequest {
    try {
      URL aUrl= new URL(url);
      String host = aUrl.getHost();
      System.out.println(host);
      if (host.startsWith("172.") || host.startsWith("192.168") || host.startsWith("10.")){
        throw new BadRequest("Use of Private IP");
      } else {
        return getLinks(url);
      }
    } catch(Exception e) {
      throw new BadRequest(e.getMessage());
    }
  }
}
