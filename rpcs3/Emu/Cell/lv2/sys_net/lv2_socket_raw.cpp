#include "stdafx.h"
#include "lv2_socket_raw.h"
#include "Emu/NP/vport0.h"
#include "sys_net_helpers.h"

LOG_CHANNEL(sys_net);

lv2_socket_raw::lv2_socket_raw(lv2_socket_family family, lv2_socket_type type, lv2_ip_protocol protocol)
	: lv2_socket(family, type, protocol)
{
}

lv2_socket_raw::lv2_socket_raw(utils::serial& ar, lv2_socket_type type)
	: lv2_socket(ar, type)
{
}

lv2_socket_raw::~lv2_socket_raw()
{
	std::lock_guard lock(mutex);
	if (socket)
	{
#ifdef _WIN32
		::closesocket(socket);
#else
		::close(socket);
#endif
	}
}

void lv2_socket_raw::save(utils::serial& ar)
{
	static_cast<lv2_socket*>(this)->save(ar, true);
}

std::tuple<bool, s32, std::shared_ptr<lv2_socket>, sys_net_sockaddr> lv2_socket_raw::accept([[maybe_unused]] bool is_lock)
{
	sys_net.todo("[RAW] accept() called on a RAW socket");
	return {};
}

std::optional<s32> lv2_socket_raw::connect([[maybe_unused]] const sys_net_sockaddr& addr)
{
	sys_net.todo("[RAW] connect() called on a RAW socket");
	return CELL_OK;
}

s32 lv2_socket_raw::connect_followup()
{
	sys_net.todo("[RAW] connect_followup() called on a RAW socket");
	return CELL_OK;
}

std::pair<s32, sys_net_sockaddr> lv2_socket_raw::getpeername()
{
	sys_net.todo("[RAW] getpeername() called on a RAW socket");
	return {};
}

s32 lv2_socket_raw::listen([[maybe_unused]] s32 backlog)
{
	sys_net.todo("[RAW] listen() called on a RAW socket");
	return {};
}

s32 lv2_socket_raw::bind([[maybe_unused]] const sys_net_sockaddr& addr)
{
	sys_net.todo("lv2_socket_raw::bind");
	return {};
}

std::pair<s32, sys_net_sockaddr> lv2_socket_raw::getsockname()
{
	sys_net.todo("lv2_socket_raw::getsockname");
	return {};
}

std::tuple<s32, lv2_socket::sockopt_data, u32> lv2_socket_raw::getsockopt([[maybe_unused]] s32 level, [[maybe_unused]] s32 optname, [[maybe_unused]] u32 len)
{
	sys_net.todo("lv2_socket_raw::getsockopt");
	return {};
}

s32 lv2_socket_raw::setsockopt(s32 level, s32 optname, const std::vector<u8>& optval)
{
	sys_net.todo("lv2_socket_raw::setsockopt(level=0x%x, optname=0x%x)", level, optname);

	// TODO
	int native_int = *reinterpret_cast<const be_t<s32>*>(optval.data());
	sys_net.todo("lv2_socket_raw native_int=%d", native_int);

	WSADATA ws;

	if (WSAStartup(MAKEWORD(2, 2), &ws) != 0)
	{
		sys_net.todo("WSAStartup() failed: %d", WSAGetLastError());
		WSACleanup();
		return {};
	}

	ensure(family == SYS_NET_AF_INET);
	ensure(protocol == SYS_NET_IPPROTO_ICMP);
	ensure(type == SYS_NET_SOCK_RAW);
	socket_type socket_res = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	sys_net.todo("raw socket return: 0x%x", socket_res);
	if (socket_res < 0 || socket_res == INVALID_SOCKET)
	{
		sys_net.todo("getlasterror raw socket: 0x%x", get_last_error(false, socket_res));
		sys_net.todo("WSAGetLastError: 0x%x", WSAGetLastError());
	}
	

	this->socket = socket_res;

	//::setsockopt(socket_res, SOL_SOCKET, SO_REUSE_UNICASTPORT
	
	sockaddr_in sadr;
	sadr.sin_family = AF_INET;
	sadr.sin_addr.s_addr = inet_addr("127.0.0.1");
	sadr.sin_port = htons(0);

	::bind(this->socket, (struct sockaddr*)&sadr, sizeof(sadr));

	if (::setsockopt(this->socket, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof(optval)) <= -1)
	{
		sys_net.todo("Error in setsockopt(): %d\n", WSAGetLastError());
	}

	if (level == SYS_NET_SOL_SOCKET && optname == SYS_NET_SO_NBIO)
	{
		// where socketfd is the socket you want to make non-blocking
		u_long mode = 1;
		int bruh = ioctlsocket(this->socket, FIONBIO, &mode);

		if (bruh != NO_ERROR)
		{
			sys_net.todo("sock_raw: failed to set non blocking: 0x%x", bruh);
			// handle the error.  By the way, I've never seen fcntl fail in this way
		}
		else
		{
			sys_net.todo("sock_raw: Successfully set socket to non-blocking mode");
		}
		
		so_nbio = native_int;
	}

	return {};
}

std::optional<std::tuple<s32, std::vector<u8>, sys_net_sockaddr>> lv2_socket_raw::recvfrom(s32 flags, [[maybe_unused]] u32 len, [[maybe_unused]] bool is_lock)
{
	std::unique_lock<shared_mutex> lock(mutex, std::defer_lock);

	if (is_lock)
	{
		lock.lock();
	}
	sys_net.todo("lv2_socket_raw::recvfrom(flags=0x%x, len=0x%x, isLock=%d)", flags, len, is_lock);

	int native_flags = 0;
	::sockaddr_storage native_addr{};
	::socklen_t native_addrlen = sizeof(native_addr);
	std::vector<u8> res_buf(len);
	//TODO make call respect non blocking

	if (flags & SYS_NET_MSG_PEEK)
	{
		native_flags |= MSG_PEEK;
	}

	if (flags & SYS_NET_MSG_WAITALL)
	{
		native_flags |= MSG_WAITALL;
	}
	sys_net.todo("lv2_socket_raw::recvfrom - socket fd is %d", this->socket);
	auto native_result = ::recvfrom(socket, reinterpret_cast<char*>(res_buf.data()), len, native_flags, reinterpret_cast<struct sockaddr*>(&native_addr), &native_addrlen);
	sys_net.todo("raw socket recvfrom returned 0x%x", native_result);
	if (native_result < 0 && WSAGetLastError() != WSAEWOULDBLOCK)
	{
		sys_net.todo("socket recv error: 0x%x", get_last_error(false, native_result));
		sys_net.todo("WSAGetLastError: 0x%x", WSAGetLastError());
		return {{-SYS_NET_EWOULDBLOCK, {}, {}}};
	}

	if (native_result >= 0)
	{
		const auto sn_addr = native_addr_to_sys_net_addr(native_addr);
		return {{::narrow<s32>(native_result), res_buf, sn_addr}};
	}

	if (so_nbio || (flags & SYS_NET_MSG_DONTWAIT))
	{
		return {{-SYS_NET_EWOULDBLOCK, {}, {}}};
	}

	const auto result = get_last_error(!so_nbio && (flags & SYS_NET_MSG_DONTWAIT) == 0);
	if (result)
		return {{-result, {}, {}}};

	return std::nullopt;
}

std::optional<s32> lv2_socket_raw::sendto([[maybe_unused]] s32 flags, [[maybe_unused]] const std::vector<u8>& buf, [[maybe_unused]] std::optional<sys_net_sockaddr> opt_sn_addr, [[maybe_unused]] bool is_lock)
{
	bool hasVal = opt_sn_addr.has_value();

	const char* msg = reinterpret_cast<const char*>(buf.data());
	sys_net.todo("lv2_socket_raw::sendto(flags=0x%x, addrHasValue=%d, isLock=%d)", flags, hasVal, is_lock);
	if (opt_sn_addr.has_value())
	{
		sys_net_sockaddr toaddr = opt_sn_addr.value();
		sockaddr_in native = sys_net_addr_to_native_addr(toaddr);
		int size = sizeof(native);
		int native_result = ::sendto(this->socket, msg, buf.size(), 0, (sockaddr*)&native, size);
		sys_net.todo("sock_raw send returned 0x%x", native_result);
		if (native_result < 0)
		{
			sys_net.todo("socket send error: 0x%x", get_last_error(false, native_result));
			sys_net.todo("WSAGetLastError: 0x%x", WSAGetLastError());
			return {0};
		}
		return {buf.size()};
	}

	return {-1};
}

std::optional<s32> lv2_socket_raw::sendmsg([[maybe_unused]] s32 flags, [[maybe_unused]] const sys_net_msghdr& msg, [[maybe_unused]] bool is_lock)
{
	sys_net.todo("lv2_socket_raw::sendmsg");
	return {};
}

void lv2_socket_raw::close()
{
	sys_net.todo("lv2_socket_raw::close");
}

s32 lv2_socket_raw::shutdown([[maybe_unused]] s32 how)
{
	sys_net.todo("lv2_socket_raw::shutdown");
	return {};
}

s32 lv2_socket_raw::poll([[maybe_unused]] sys_net_pollfd& sn_pfd, [[maybe_unused]] pollfd& native_pfd)
{
	sys_net.todo("lv2_socket_raw::poll");
	return {};
}

std::tuple<bool, bool, bool> lv2_socket_raw::select([[maybe_unused]] bs_t<lv2_socket::poll_t> selected, [[maybe_unused]] pollfd& native_pfd)
{
	sys_net.todo("lv2_socket_raw::select");
	return {};
}
