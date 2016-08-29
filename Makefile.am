sbin_PROGRAMS = \
	netipmid

netipmid_SOURCES = \
	main.cpp \
	socket_channel.cpp \
	auth_algo.cpp \
	session.cpp \
	message_parsers.cpp \
	sessions_manager.cpp \
	command_table.cpp \
	message_handler.cpp \
	comm_module.cpp

netipmid_LDFLAGS = $(SYSTEMD_LIBS) $(libmapper_LIBS)
