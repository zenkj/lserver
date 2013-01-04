local logger = console.logger

local function main()
    local ok, client = tcp.createClient('127.0.0.1', 4321)
    if not ok then
        local err = client
        logger:log('connect to server failed: ' .. err.msg)
        return
    end

    client:write 'hello'
    local ok, data = client:read()
    if not ok then
        local err = data
        logger:log('read data failed: ' .. err.msg)
        return
    end
    logger:log(data)
end

main()
