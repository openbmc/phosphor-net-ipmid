#include <assert.h>
#include <dlfcn.h>
#include <dirent.h>
#include <mapper.h>
#include <unistd.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>

#include <ipmiSockChannelData.H>
#include <ipmiMessageHandler.H>
#include <ipmiCommModule.H>

FILE *ipmiio, *ipmidbus, *ipmicmddetails;

#define MAX_DBUS_PATH 128
struct dbus_interface_t {
    uint8_t  sensornumber;
    uint8_t  sensortype;

    char  bus[MAX_DBUS_PATH];
    char  path[MAX_DBUS_PATH];
    char  interface[MAX_DBUS_PATH];
};

unsigned short g_sel_reserve = 0xFFFF;
sd_bus *bus = NULL;
sd_bus_slot *ipmid_slot = NULL;
unsigned short get_sel_reserve_id(void)
{
    return g_sel_reserve;
}

sd_bus *ipmid_get_sd_bus_connection(void) {
    return bus;
}

// Use a lookup table to find the interface name of a specific sensor
// This will be used until an alternative is found.  this is the first
// step for mapping IPMI
int find_interface_property_fru_type(dbus_interface_t *interface, const char *property_name, char *property_value) {

    char  *str1;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL, *m=NULL;


    int r;

    r = sd_bus_message_new_method_call(bus,&m,interface->bus,interface->path,"org.freedesktop.DBus.Properties","Get");
    if (r < 0) {
        fprintf(stderr, "Failed to create a method call: %s", strerror(-r));
        fprintf(stderr,"Bus: %s Path: %s Interface: %s \n",
                interface->bus, interface->path, interface->interface);
        goto final;
    }

    r = sd_bus_message_append(m, "ss", "org.openbmc.InventoryItem", property_name);
    if (r < 0) {
        fprintf(stderr, "Failed to create a input parameter: %s", strerror(-r));
        fprintf(stderr,"Bus: %s Path: %s Interface: %s \n",
                interface->bus, interface->path, interface->interface);
        goto final;
    }

    r = sd_bus_call(bus, m, 0, &error, &reply);
    if (r < 0) {
        fprintf(stderr, "Failed to call the method: %s", strerror(-r));
        goto final;
    }

    r = sd_bus_message_read(reply, "v",  "s", &str1) ;
    if (r < 0) {
        fprintf(stderr, "Failed to get a response: %s", strerror(-r));
        goto final;
    }

    strcpy(property_value, str1);

final:

    sd_bus_error_free(&error);
    m = sd_bus_message_unref(m);
    reply = sd_bus_message_unref(reply);

    return r;
}


sd_bus_slot *ipmid_get_sd_bus_slot(void) {
    return ipmid_slot;
}

int find_openbmc_path(const char *type, const uint8_t num, dbus_interface_t *interface) {
    char  *busname = NULL;
    const char  *iface = "org.openbmc.managers.System";
    const char  *objname = "/org/openbmc/managers/System";
    char  *str1 = NULL, *str2, *str3;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;


    int r;
    r = mapper_get_service(bus, objname, &busname);
    if (r < 0) {
        fprintf(stderr, "Failed to get system manager busname: %s\n", strerror(-r));
        goto final;
    }

    r = sd_bus_call_method(bus,busname,objname,iface, "getObjectFromByteId",
                           &error, &reply, "sy", type, num);
    if (r < 0) {
        fprintf(stderr, "Failed to create a method call: %s", strerror(-r));
        goto final;
    }

    r = sd_bus_message_read(reply, "(ss)", &str2, &str3);
    if (r < 0) {
        fprintf(stderr, "Failed to get a response: %s", strerror(-r));
        goto final;
    }

    r = mapper_get_service(bus, str2, &str1);
    if (r < 0) {
        fprintf(stderr, "Failed to get item busname: %s\n", strerror(-r));
        goto final;
    }

    strncpy(interface->bus, str1, MAX_DBUS_PATH);
    strncpy(interface->path, str2, MAX_DBUS_PATH);
    strncpy(interface->interface, str3, MAX_DBUS_PATH);

    interface->sensornumber = num;

final:

    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);
    free(str1);

    return r;
}

int set_sensor_dbus_state_s(uint8_t number, const char *method, const char *value) {


    dbus_interface_t a;
    int r;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m=NULL;

    fprintf(ipmidbus, "Attempting to set a dbus Variant Sensor 0x%02x via %s with a value of %s\n",
        number, method, value);

    r = find_openbmc_path("SENSOR", number, &a);

    if (r < 0) {
        fprintf(stderr, "Failed to find Sensor 0x%02x\n", number);
        return 0;
    }

    r = sd_bus_message_new_method_call(bus,&m,a.bus,a.path,a.interface,method);
    if (r < 0) {
        fprintf(stderr, "Failed to create a method call: %s", strerror(-r));
        goto final;
    }

    r = sd_bus_message_append(m, "v", "s", value);
    if (r < 0) {
        fprintf(stderr, "Failed to create a input parameter: %s", strerror(-r));
        goto final;
    }


    r = sd_bus_call(bus, m, 0, &error, NULL);
    if (r < 0) {
        fprintf(stderr, "Failed to call the method: %s", strerror(-r));
    }

final:
    sd_bus_error_free(&error);
    m = sd_bus_message_unref(m);

    return 0;
}
int set_sensor_dbus_state_y(uint8_t number, const char *method, const uint8_t value) {


    dbus_interface_t a;
    int r;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m=NULL;

    fprintf(ipmidbus, "Attempting to set a dbus Variant Sensor 0x%02x via %s with a value of 0x%02x\n",
        number, method, value);

    r = find_openbmc_path("SENSOR", number, &a);

    if (r < 0) {
        fprintf(stderr, "Failed to find Sensor 0x%02x\n", number);
        return 0;
    }

    r = sd_bus_message_new_method_call(bus,&m,a.bus,a.path,a.interface,method);
    if (r < 0) {
        fprintf(stderr, "Failed to create a method call: %s", strerror(-r));
        goto final;
    }

    r = sd_bus_message_append(m, "v", "i", value);
    if (r < 0) {
        fprintf(stderr, "Failed to create a input parameter: %s", strerror(-r));
        goto final;
    }


    r = sd_bus_call(bus, m, 0, &error, NULL);
    if (r < 0) {
        fprintf(stderr, "12 Failed to call the method: %s", strerror(-r));
    }

final:
    sd_bus_error_free(&error);
    m = sd_bus_message_unref(m);

    return 0;
}

// Plugin libraries need to _end_ with .so
#define IPMI_PLUGIN_EXTN ".so"
// Plugin libraries can be versioned with suffix .so.*
#define IPMI_PLUGIN_SONAME_EXTN ".so."

int handler_select(const struct dirent *entry)
{
    // To hold ".so" from entry->d_name;
    char dname_copy[4] = {0};

    // We want to avoid checking for everything and isolate to the ones having
    // .so.* or .so in them.
    // Check for versioned libraries .so.*
    if(strstr(entry->d_name, IPMI_PLUGIN_SONAME_EXTN))
    {
        return 1;
    }
    // Check for non versioned libraries .so
    else if(strstr(entry->d_name, IPMI_PLUGIN_EXTN))
    {
        // It is possible that .so could be anywhere in the string but unlikely
        // But being careful here. Get the base address of the string, move
        // until end and come back 3 steps and that gets what we need.
        strcpy(dname_copy, (entry->d_name + strlen(entry->d_name)-strlen(IPMI_PLUGIN_EXTN)));
        if(strcmp(dname_copy, IPMI_PLUGIN_EXTN) == 0)
        {
            return 1;
        }
    }
    return 0;
}


// Method that gets called by shared libraries to get their command handlers registered
void ipmi_register_callback(ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_context_t context,
                            ipmid_callback_t handler) {
  IpmiCommandTable::IpmiCommandTableEntry l_entry;

  uint16_t net_fun = netfn<<10;
  l_entry.CommandID.cmdCode = (IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI<<16)|net_fun | cmd;
  l_entry.concreteCommand = nullptr;
  l_entry.concreteCallBackCommand = handler;
  l_entry.canExecuteSessionless = false;
  l_entry.privilegeMask = IpmiCommandTable::IPMI_SESSION_PRIVILEGE_ANY;
  l_entry.supportedChannels = IpmiCommandTable::IPMI_CHANNEL_ANY;
  l_entry.commandSupportMask = IpmiCommandTable::IPMI_COMMAND_SUPPORT_NO_DISABLE;

  IpmiCommandTable::getInstance().Register(l_entry);
}

void ipmi_register_callback_handlers(const char* ipmi_lib_path)
{
    // For walking the ipmi_lib_path
    struct dirent **handler_list;
    int num_handlers = 0;

    // This is used to check and abort if someone tries to register a bad one.
    void *lib_handler = NULL;

    if(ipmi_lib_path == NULL)
    {
        fprintf(stderr,"ERROR; No handlers to be registered for ipmi.. Aborting\n");
        assert(0);
    }
    else
    {
        // 1: Open ipmi_lib_path. Its usually "/usr/lib/phosphor-host-ipmid"
        // 2: Scan the directory for the files that end with .so
        // 3: For each one of them, just do a 'dlopen' so that they register
        //    the handlers for callback routines.

        std::string handler_fqdn = ipmi_lib_path;

        // Append a "/" since we need to add the name of the .so. If there is
        // already a .so, adding one more is not any harm.
        handler_fqdn += "/";

        num_handlers = scandir(ipmi_lib_path, &handler_list, handler_select, alphasort);
        if (num_handlers < 0)
            return;

        while(num_handlers--)
        {
            handler_fqdn = ipmi_lib_path;
            handler_fqdn += handler_list[num_handlers]->d_name;
            printf("Registering handler:[%s]\n",handler_fqdn.c_str());

            lib_handler = dlopen(handler_fqdn.c_str(), RTLD_NOW);

            if(lib_handler == NULL)
            {
                fprintf(stderr,"ERROR opening [%s]: %s\n",
                        handler_fqdn.c_str(), dlerror());
            }
            // Wipe the memory allocated for this particular entry.
            free(handler_list[num_handlers]);
        }

        // Done with all registration.
        free(handler_list);
    }

    // TODO : What to be done on the memory that is given by dlopen ?.
    return;
}

static int io_handler(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
  std::shared_ptr<IpmiSockChannelData> l_pChannel;

  l_pChannel.reset(new IpmiSockChannelData(dup(fd)));

  // Initialize a Message Handler with the fd

  IpmiMessageHandler l_ipmiMsgHndl(l_pChannel);

  // Read the Packet
  l_ipmiMsgHndl.receive();

  // Execute the Command
  l_ipmiMsgHndl.route();

  // Send the Packet
  l_ipmiMsgHndl.send();

  return 0;
}

int main(int i_argc, char* i_argv[]) {
  union {
    struct sockaddr_in in;
    struct sockaddr sa;
  } sa;

  sd_event_source *event_source = nullptr;
  sd_event *event = nullptr;
  int fd = -1, r;
  sigset_t ss;

  r = sd_event_default(&event);
  if (r < 0) goto finish;

  if (sigemptyset(&ss) < 0 || sigaddset(&ss, SIGTERM) < 0 || sigaddset(&ss, SIGINT) < 0) {
    r = -errno;
    goto finish;
  }

  /* Block SIGTERM first, so that the event loop can handle it */
  if (sigprocmask(SIG_BLOCK, &ss, NULL) < 0) {
    r = -errno;
    goto finish;
  }

  /* Let's make use of the default handler and "floating" reference features of sd_event_add_signal() */
  r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
  if (r < 0) goto finish;

  r = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
  if (r < 0) goto finish;

  fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
  if (fd < 0) {
    r = -errno;
    goto finish;
  }

  sa.in = (struct sockaddr_in) {
    .sin_family = AF_INET,
    .sin_port = htobe16(623),
  };

  if (bind(fd, &sa.sa, sizeof(sa)) < 0) {
    r = -errno;
    goto finish;
  }

  r = sd_event_add_io(event, &event_source, fd, EPOLLIN, io_handler, NULL);
  if (r < 0) goto finish;

  //Register the RAKP related commands
  registerCommands();

  /* Connect to system bus */
   r = sd_bus_open_system(&bus);
   if (r < 0) {
       fprintf(stderr, "Failed to connect to system bus: %s\n",
               strerror(-r));
       goto finish;
   }

  // Register all the handlers that provider implementation to IPMI commands.
  ipmi_register_callback_handlers(HOST_IPMI_LIB_PATH);

  r = sd_event_loop(event);

finish:
  event_source = sd_event_source_unref(event_source);
  event = sd_event_unref(event);
  sd_bus_unref(bus);

  if (fd >= 0)
    (void) close(fd);

  if (r < 0)
    fprintf(stderr, "Failure: %s\n", strerror(-r));

  return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

  //We will never get here .. but in case we do .. return 0 to OS.
  return 0;
}
