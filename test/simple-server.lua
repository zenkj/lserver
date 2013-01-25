local clientfunc = function(client, server)
    while true do
        print "client waiting data..."
        local ok, data = client:read()
        if not ok then
            local err = data
            print('client read failed: ' .. err.msg)
            break
        end
        print(data)
        client:write(data)
        if data == 'quit\r\n' then server:close() end
        if data == 'exit\r\n' then break end
    end
    client:close()
end

local function main()
    local ok, server = tcp.createServer('127.0.0.1', 4321)
    if not ok then
        local err = server
        print('create server failed: ' .. err.msg)
        return
    end
    print "server created"
    print (server)

    while true do
        local ok, client = server:accept()
        if not ok then
            local err = client
            print('server accept error: ' .. err.msg)
            break
        end
        print "new client accepted"
        print (client)

        client:setTimeout(1000*1000)
        local mth = coroutine.create(clientfunc)
        coroutine.resume(mth, client, server)
    end
end

main()

