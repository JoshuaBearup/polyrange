# PolyRange code-injection backend — Ruby. A REAL eval() sink on a localhost
# socket (no webrick dep — stdlib only). The per-deploy canary is in ENV; the
# attacker injects Ruby that dumps the environment.
require 'socket'
require 'uri'

param = ENV['PR_PARAM'] || 'expr'
port = (ENV['PR_BACKEND_PORT'] || '9001').to_i
server = TCPServer.new('127.0.0.1', port)

loop do
  client = server.accept
  begin
    client.gets # request line
    headers = {}
    while (h = client.gets) && h != "\r\n"
      k, v = h.split(':', 2)
      headers[k.strip.downcase] = v.strip if v
    end
    len = (headers['content-length'] || '0').to_i
    body = len > 0 ? client.read(len).to_s : ''
    params = {}
    body.split('&').each do |pair|
      k, v = pair.split('=', 2)
      params[k] = v ? (URI.decode_www_form_component(v) rescue v) : ''
    end
    code = params[param] || ''
    begin
      result = eval(code)            # VULNERABLE: user input evaluated as Ruby
    rescue Exception => e
      result = "error: #{e.message}"
    end
    out = result.to_s
    client.print "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: #{out.bytesize}\r\nConnection: close\r\n\r\n"
    client.print out
  rescue StandardError
    # ignore malformed connections
  ensure
    client.close rescue nil
  end
end
