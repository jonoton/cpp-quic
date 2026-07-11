add_executable(quic_server server.cpp)
target_link_libraries(quic_server PRIVATE cppquic::cppquic)

add_executable(quic_client client.cpp)
target_link_libraries(quic_client PRIVATE cppquic::cppquic)

add_executable(quic_stream_transfer stream_transfer.cpp)
target_link_libraries(quic_stream_transfer PRIVATE cppquic::cppquic)

add_executable(quic_throughput throughput.cpp)
target_link_libraries(quic_throughput PRIVATE cppquic::cppquic)

