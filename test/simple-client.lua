local function main()
    tcp.connect_timeout = 1000*1000
    local ok, client = tcp.createClient('127.0.0.1', 4321)
    if not ok then
        local err = client
        print('connect to server failed: ' .. err.msg)
        return
    end
    print ('client: ' .. tostring(client))

    client:write 'hello from client'
    local ok, data = client:read()
    if not ok then
        local err = data
        print('read data failed: ' .. err.msg)
        return
    end
    print("read: " .. data)

    mthread.sleep(3*1000)

    client:write 'hello after 3 seconds'
    ok, data = client:read()
    if not ok then
        local err = data
        print('read data failed: ' .. err.msg)
        return
    end
    print("read: " .. data)
end

main()
