#include <unistd.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>

#include <ipmiSockChannelData.H>
#include <ipmiMessageHandler.H>
#include <ipmiCommModule.H>

static int io_handler(sd_event_source* es, int fd, uint32_t revents,
                      void* userdata)
{
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

int main(int i_argc, char* i_argv[])
{
    union
    {
        struct sockaddr_in in;
        struct sockaddr sa;
    } sa;

    sd_event_source* event_source = nullptr;
    sd_event* event = nullptr;
    int fd = -1, r;
    sigset_t ss;

    r = sd_event_default(&event);
    if (r < 0)
    {
        goto finish;
    }

    if (sigemptyset(&ss) < 0 || sigaddset(&ss, SIGTERM) < 0 ||
        sigaddset(&ss, SIGINT) < 0)
    {
        r = -errno;
        goto finish;
    }

    /* Block SIGTERM first, so that the event loop can handle it */
    if (sigprocmask(SIG_BLOCK, &ss, NULL) < 0)
    {
        r = -errno;
        goto finish;
    }

    /* Let's make use of the default handler and "floating" reference features of sd_event_add_signal() */
    r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
    if (r < 0)
    {
        goto finish;
    }

    r = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
    if (r < 0)
    {
        goto finish;
    }

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
    {
        r = -errno;
        goto finish;
    }

    sa.in = (struct sockaddr_in)
    {
        .sin_family = AF_INET,
         .sin_port = htobe16(623),
    };

    if (bind(fd, &sa.sa, sizeof(sa)) < 0)
    {
        r = -errno;
        goto finish;
    }

    r = sd_event_add_io(event, &event_source, fd, EPOLLIN, io_handler, NULL);
    if (r < 0)
    {
        goto finish;
    }

    //Register the RAKP related commands
    registerCommands();

    r = sd_event_loop(event);

finish:
    event_source = sd_event_source_unref(event_source);
    event = sd_event_unref(event);

    if (fd >= 0)
    {
        (void) close(fd);
    }

    if (r < 0)
    {
        fprintf(stderr, "Failure: %s\n", strerror(-r));
    }

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    //We will never get here .. but in case we do .. return 0 to OS.
    return 0;
}
