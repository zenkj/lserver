local logger = console.logger

local clientfunc = function(client)
    while true do
        local ok, data = client:read()
        if not ok then
            local err = data
            logger:log('client read failed: ' .. err.msg)
            break
        end
        logger:log(data)
        client:write(data)
    end
end

local function main()
    local ok, server = tcp.createServer('127.0.0.1', 4321)
    if not ok then
        local err = server
        logger:log('create server failed: ' .. err.msg)
        return
    end

    while true do
        local ok, client = server:accept()
        if not ok then
            local err = client
            logger:log('server accept error: ' .. err.msg)
            break
        end
        local mth = mthread.create(clientfunc, client)
        mth:start()
    end
end

main()

