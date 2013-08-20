#lserver
lua server based on libuv.

combine lua's coroutine and libuv's non-block io, the result is synchronous non-block client and server.

#example
look at 'test' directory for example.

#note at 2013/8/20
a long time no updating.

After investigation these days, I feel the coroutine style may not be so useful. coroutine means non-preemptive
schedule, which is what early versions of Windows support. Now the main stream of OS use preemptive schedule.
As a platform, lserver is similar to OS, it will run all kinds of framework, library along with your own
business code. The whole lserver is easy to be locked by some trivial 3rd party library with coroutine style.
These days i've read much erlang code. erlang runtime support real preemptive schedule with light weight process.
erlang has many good parts. before it's possible to support real preemptive schedule(via the debug api?) and some
other features of erlang(e.g., non-rebinding variables) in lua, lserver will cease for some time.
