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
	comm_module.cpp \
	command/channel_auth.cpp \
	command/guid.cpp \
	command/open_session.cpp \
	command/rakp12.cpp \
	command/rakp34.cpp \
	command/session_cmds.cpp

netipmid_LDFLAGS = $(SYSTEMD_LIBS) $(libmapper_LIBS)

