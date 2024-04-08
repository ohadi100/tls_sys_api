add_library(streams OBJECT
	${CMAKE_CURRENT_SOURCE_DIR}/inetaddr/InetAddressFactory.cpp	
	${CMAKE_CURRENT_SOURCE_DIR}/inetaddr/IPInetAddressImpl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/InternIOStream/InternIOStream.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/UserIOStream/UserIOStream.cpp       
)

target_include_directories(streams PUBLIC
		"$<BUILD_INTERFACE:${INCLUDE_FILES}>"
		"$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_link_libraries(streams
	PRIVATE
	Threads::Threads
	${AMSR_COMPONENTS}
)

foreach (ENGINE ${ENGINE_TYPES})
	# Install the library
	install(TARGETS streams
			EXPORT tls_${ENGINE}Targets
			LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
endforeach (ENGINE)