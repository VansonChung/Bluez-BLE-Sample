#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <signal.h>
#include <string.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

/* Unofficial value, might still change */
#define LE_LINK		0x80

#define FLAGS_AD_TYPE 0x01
#define FLAGS_LIMITED_MODE_BIT 0x01
#define FLAGS_GENERAL_MODE_BIT 0x02

#define EIR_FLAGS                   0x01  /* flags */
#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define EIR_TX_POWER                0x0A  /* transmit power level */
#define EIR_DEVICE_ID               0x10  /* device ID */

#define CMD_HELP                    "help"
#define CMD_INFO                    "info"
#define CMD_UP                      "up"
#define CMD_DOWN                    "down"
#define CMD_REST                    "reset"
#define CMD_CON_INFO                "conInfo"
#define CMD_SCAN                    "scan"
#define CMD_CONNECT                 "connect"
#define CMD_DISCONNECT              "disconnect"
#define CMD_EXIT                    "exit"

#define UNKNOWN_DEVICES             "(unknown)"

static volatile int signal_received = 0;

void help() {
    printf("Commands:\n"
            "\thelp            Display help\n"
            "\tinfo            Get information from local device\n"
	        "\tup              Open and initialize device\n"
	        "\tdown            Close device\n"
	        "\treset           Reset device\n"
	        "\tconInfo         Display active connections\n"
	        "\tscan            Start LE scan (display 10 result devices)\n"
	        "\tconnect         Create a LE Connection\n"
	        "\tdisconnect      Disconnect a LE Connection\n"
	        "\texit            Exit\n");
}

void info() {
    system("hciconfig");
    int dev_id, err, dd;
    dev_id = hci_get_route(NULL);
    printf("dev_id = %d\n", dev_id);
	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("Could not open device");
		return;
	} else {
        printf("hci_open_dev success %d\n", dd);
    }
	hci_close_dev(dd);
}

void up(int dev_id)
{
    int ctl;
	/* Open HCI socket  */
	if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		perror("Can't open HCI socket.");
		return;
	}

	/* Start HCI device */
	if (ioctl(ctl, HCIDEVUP, dev_id) < 0) {
		if (errno == EALREADY)
			return;
		fprintf(stderr, "Can't init device hci%d: %s (%d)\n",
						dev_id, strerror(errno), errno);
	}

    close(ctl);
}

void down(int dev_id)
{
    int ctl;
	/* Open HCI socket  */
	if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		perror("Can't open HCI socket.");
		return;
	}

	/* Stop HCI device */
	if (ioctl(ctl, HCIDEVDOWN, dev_id) < 0) {
		fprintf(stderr, "Can't down device hci%d: %s (%d)\n",
						dev_id, strerror(errno), errno);
	}

    close(ctl);
}

/* Can't get dev_id by hci_get_route when the bt is down, so we need dev_id by user（easier than parse hciconfig） */
void reset(int dev_id)
{
	down(dev_id);
	up(dev_id);
}

char *type2str(uint8_t type)
{
	switch (type) {
	case SCO_LINK:
		return "SCO";
	case ACL_LINK:
		return "ACL";
	case ESCO_LINK:
		return "eSCO";
	case LE_LINK:
		return "LE";
	default:
		return "Unknown";
	}
}

int conn_list(int s, int dev_id, long arg)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	int id = arg;
	int i;

	if (id != -1 && dev_id != id)
		return 0;

	if (!(cl = malloc(10 * sizeof(*ci) + sizeof(*cl)))) {
		perror("Can't allocate memory");
		exit(1);
	}
	cl->dev_id = dev_id;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(s, HCIGETCONNLIST, (void *) cl)) {
		perror("Can't get connection list");
		exit(1);
	}

	for (i = 0; i < cl->conn_num; i++, ci++) {
		char addr[18];
		char *str;
		ba2str(&ci->bdaddr, addr);
		str = hci_lmtostr(ci->link_mode);
		printf("\t%s %s %s handle %d state %d lm %s\n",
			ci->out ? "<" : ">", type2str(ci->type),
			addr, ci->handle, ci->state, str);
		bt_free(str);
	}

	free(cl);
	return 0;
}

void con_info()
{
    int dev_id;
    dev_id = hci_get_route(NULL);
	printf("Connections:\n");
	hci_for_each_dev(HCI_UP, conn_list, dev_id);
}

void sigint_handler(int sig)
{
	signal_received = sig;
}

int read_flags(uint8_t *flags, const uint8_t *data, size_t size)
{
	size_t offset;

	if (!flags || !data)
		return -EINVAL;

	offset = 0;
	while (offset < size) {
		uint8_t len = data[offset];
		uint8_t type;

		/* Check if it is the end of the significant part */
		if (len == 0)
			break;

		if (len + offset > size)
			break;

		type = data[offset + 1];

		if (type == FLAGS_AD_TYPE) {
			*flags = data[offset + 2];
			return 0;
		}

		offset += 1 + len;
	}

	return -ENOENT;
}

int check_report_filter(uint8_t procedure, le_advertising_info *info)
{
	uint8_t flags;

	/* If no discovery procedure is set, all reports are treat as valid */
	if (procedure == 0)
		return 1;

	/* Read flags AD type value from the advertising report if it exists */
	if (read_flags(&flags, info->data, info->length))
		return 0;

	switch (procedure) {
	case 'l': /* Limited Discovery Procedure */
		if (flags & FLAGS_LIMITED_MODE_BIT)
			return 1;
		break;
	case 'g': /* General Discovery Procedure */
		if (flags & (FLAGS_LIMITED_MODE_BIT | FLAGS_GENERAL_MODE_BIT))
			return 1;
		break;
	default:
		fprintf(stderr, "Unknown discovery procedure\n");
	}

	return 0;
}

void eir_parse_name(uint8_t *eir, size_t eir_len,
						char *buf, size_t buf_len)
{
	size_t offset;

	offset = 0;
	while (offset < eir_len) {
		uint8_t field_len = eir[0];
		size_t name_len;

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		if (offset + field_len > eir_len)
			goto failed;

		switch (eir[1]) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			name_len = field_len - 1;
			if (name_len > buf_len)
				goto failed;

			memcpy(buf, &eir[2], name_len);
			return;
		}

		offset += field_len + 1;
		eir += field_len + 1;
	}

failed:
	snprintf(buf, buf_len, "(unknown)");
}

int print_advertising_devices(int dd, uint8_t filter_type)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	struct hci_filter nf, of;
	struct sigaction sa;
	socklen_t olen;
	int len;

	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
		printf("Could not get socket options\n");
		return -1;
	}

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);

	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		printf("Could not set socket options\n");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sigint_handler;
	sigaction(SIGINT, &sa, NULL);

	/* Wait for 10 report events */
	int num = 10;
	while (num > 0) {  // while (num--) {
		evt_le_meta_event *meta;
		le_advertising_info *info;
		char addr[18];

		while ((len = read(dd, buf, sizeof(buf))) < 0) {
			if (errno == EINTR && signal_received == SIGINT) {
				len = 0;
				goto done;
			}

			if (errno == EAGAIN || errno == EINTR)
				continue;
			goto done;
		}

		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		meta = (void *) ptr;

		if (meta->subevent != 0x02)
			goto done;

		/* Ignoring multiple reports */
		info = (le_advertising_info *) (meta->data + 1);
		if (check_report_filter(filter_type, info)) {
			char name[30];

			memset(name, 0, sizeof(name));

			ba2str(&info->bdaddr, addr);
			eir_parse_name(info->data, info->length,
							name, sizeof(name) - 1);

			if (strcmp(name, UNKNOWN_DEVICES)) {
                num--;
                printf("%s, %s\n", addr, name);
            } 
		}
	}
done:
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	if (len < 0)
		return -1;
	return 0;
}

void lescan()
{
	int dev_id, err, dd;
	uint8_t own_type = LE_PUBLIC_ADDRESS;
	uint8_t scan_type = 0x01;
	uint8_t filter_type = 0;
	uint8_t filter_policy = 0x00;
	uint16_t interval = htobs(0x0010);
	uint16_t window = htobs(0x0010);
	uint8_t filter_dup = 0x01;

    dev_id = hci_get_route(NULL);

    dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("Could not open device");
		return;
	}

	err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
						own_type, filter_policy, 10000);
	if (err < 0) {
		perror("Set scan parameters failed");
		goto done;
	}

    printf("LE Scan enable on\n");
	err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 10000);
	if (err < 0) {
		perror("Enable scan failed");
		goto done;
	}

	printf("LE Scan ...\n");

	err = print_advertising_devices(dd, filter_type);
	if (err < 0) {
		perror("Could not receive advertising events");
		goto done;
	}

    printf("LE Scan enable off\n");
	err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 10000);
	if (err < 0) {
		perror("Disable scan failed");
		goto done;
	}
done:
	hci_close_dev(dd);
}

void lecc(char *addr, bool is_random_peer_bdaddr_type)
{
	int dev_id, err, dd;
    bdaddr_t bdaddr;
	uint16_t interval, latency, max_ce_length, max_interval, min_ce_length;
	uint16_t min_interval, supervision_timeout, window, handle;
	uint8_t initiator_filter, own_bdaddr_type, peer_bdaddr_type;

    own_bdaddr_type = LE_PUBLIC_ADDRESS;
    // DM286 -> LE_RANDOM_ADDRESS
    // DM285 -> LE_PUBLIC_ADDRESS
    if (is_random_peer_bdaddr_type) {
        peer_bdaddr_type = LE_RANDOM_ADDRESS;
    } else {
        peer_bdaddr_type = LE_PUBLIC_ADDRESS;
    }
	initiator_filter = 0; /* Use peer address */
	
	dev_id = hci_get_route(NULL);
	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("Could not open device");
		return;
	}

    memset(&bdaddr, 0, sizeof(bdaddr_t));
	str2ba(addr, &bdaddr);

	interval = htobs(0x0004);
	window = htobs(0x0004);
	own_bdaddr_type = 0x00;
	min_interval = htobs(0x000F);
	max_interval = htobs(0x000F);
	latency = htobs(0x0000);
	supervision_timeout = htobs(0x0C80);
	min_ce_length = htobs(0x0001);
	max_ce_length = htobs(0x0001);

	err = hci_le_create_conn(dd, interval, window, initiator_filter,
			peer_bdaddr_type, bdaddr, own_bdaddr_type, min_interval,
			max_interval, latency, supervision_timeout,
			min_ce_length, max_ce_length, &handle, 25000);
	if (err < 0) {
		perror("Could not create connection");
		goto done;
	}

	printf("Connection handle %d\n", handle);

done:
	hci_close_dev(dd);
}

void ledc(uint16_t handle)
{
	int dev_id, err, dd;
	uint8_t reason = HCI_OE_USER_ENDED_CONNECTION;

	dev_id = hci_get_route(NULL);
	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("Could not open device");
		return;
	}

	err = hci_disconnect(dd, handle, reason, 10000);
	if (err < 0) {
		perror("Could not disconnect");
		goto done;
	}
done:
	hci_close_dev(dd);
}

int main(void) {
    char cmd[50], type[10];
    int dev_id;
    uint16_t handle;

    while (1) {
        printf("Please input cmd :\n");
        scanf("%s", &cmd);
        if (strcmp(cmd, CMD_HELP) == 0) {
            help();
        } else if (strcmp(cmd, CMD_INFO) == 0) {
            info();
        } else if (strcmp(cmd, CMD_UP) == 0) {
            printf("Please input target down device id :\n");
            scanf("%d", &dev_id);
            up(dev_id);
        } else if (strcmp(cmd, CMD_DOWN) == 0) {
            printf("Please input target up device id :\n");
            scanf("%d", &dev_id);
            down(dev_id);
        } else if (strcmp(cmd, CMD_REST) == 0) {
            printf("Please input target reset device id :\n");
            scanf("%d", &dev_id);
            reset(dev_id);
        } else if (strcmp(cmd, CMD_CON_INFO) == 0) {
            con_info();
        } else if (strcmp(cmd, CMD_SCAN) == 0) {
            lescan();
        } else if (strcmp(cmd, CMD_CONNECT) == 0) {
            printf("Please input target connect address :\n");
            scanf("%s", &cmd);
            printf("Use random peer bdaddr type ? (yes/no)\n");
            scanf("%s", &type);
            lecc(cmd, strcmp(type, "yes") == 0);
        } else if (strcmp(cmd, CMD_DISCONNECT) == 0) {
            printf("Please input target disconnect handle :\n");
            scanf("%d", &handle);
            ledc(handle);
        } else if (strcmp(cmd, CMD_EXIT) == 0) {
            exit(EXIT_SUCCESS);
        } else {
            printf("unknow cmd\n");
        }
        fflush(stdin);
    }
    return EXIT_SUCCESS;
}