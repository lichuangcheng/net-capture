add_executable(day01 "day01/main.cpp")
add_executable(day02 "day02/main.cpp")

add_executable(d89 "day089/main.cpp")
target_link_libraries(d89 netcap)

add_executable(d10 "day10/main.cpp")
target_link_libraries(d10 netcap)

add_executable(d12 "day12/main.cpp")
target_link_libraries(d12 netcap)

add_executable(mid "mid/main.cpp")
target_link_libraries(mid netcap)
