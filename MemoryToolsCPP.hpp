// Copyright (C) 2026 CZF-H
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//
// Created by wanjiangzhi on 2026/2/26.
//

#ifndef MEMORYTOOLSCPP_HPP
#define MEMORYTOOLSCPP_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <string>
#include <fstream>
#include <sstream>
#include <utility>

// For using MemoryTools_Alias;
#define MemoryTools_Alias namespace ::MemoryTools::alias

namespace MemoryTools {
    namespace alias {
        using BYTE = int8_t;
        using WORD = int16_t;
        using DWORD = int32_t;
        using QWORD = int64_t;
        using FLOAT = float;
        using DOUBLE = double;

        using B = BYTE;
        using W = WORD;
        using D = DWORD;
        using Q = QWORD;
        using F = FLOAT;
        using E = DOUBLE;
    }

    static bool ReadBuffer(uintptr_t addr, void* buffer, size_t size) {
        iovec local{};
        iovec remote{};

        local.iov_base = buffer;
        local.iov_len = size;
        remote.iov_base = reinterpret_cast<void*>(addr);
        remote.iov_len = size;

        ssize_t ret = syscall(
            SYS_process_vm_readv,
            getpid(),
            &local, 1,
            &remote, 1,
            0
        );

        return ret == static_cast<ssize_t>(size);
    }

    template<size_t bit>
    class PtrLow {
        uintptr_t local;
    public:
        explicit PtrLow(uintptr_t address) {
            uintptr_t value = 0;
            ReadBuffer(address, &value, sizeof(value));
            local = value & ((1ULL << bit) - 1);
        }
    private:
        explicit PtrLow(uintptr_t value, bool is_value) {
            local = value & ((1ULL << bit) - 1);
        }

    public:
        PtrLow Next(intptr_t offset = 0) const {
            uintptr_t addr = (local & ((1ULL << bit) - 1)) + offset;
            uintptr_t value = 0;
            ReadBuffer(addr, &value, sizeof(value));
            return PtrLow<bit>(value, true);
        }

        PtrLow& ToNext(intptr_t offset = 0) {
            local = Next(offset).value();
            return *this;
        }

        PtrLow Offset(intptr_t offset) const {
            PtrLow<bit> result = *this;
            result.local += offset;
            return result;
        }

        PtrLow operator+(intptr_t offset) const { return Offset(offset); }
        PtrLow& operator+=(intptr_t offset) {
            this->local += offset;
            return *this;
        }
        PtrLow operator-(intptr_t offset) const { return Offset(-offset); }
        PtrLow& operator-=(intptr_t offset) {
            this->local -= offset;
            return *this;
        }

        PtrLow operator>>(intptr_t offset) const { return Next(offset); }
        PtrLow& operator>>=(intptr_t offset) {
            ToNext(offset);
            return *this;
        }
        PtrLow operator()(intptr_t offset) const { return Next(offset); }

        uintptr_t value() const { return local; }
        uintptr_t operator*() const { return value(); }
        explicit operator uintptr_t() const { return value(); }
    };
    using Ptr40 = PtrLow<40>;

    class Addr {
        uintptr_t m_addr{};

        static long pageSize() {
            static long ps = sysconf(_SC_PAGESIZE);
            return ps > 0 ? ps : 4096; // fallback
        }

        void* pageStart() const {
            return reinterpret_cast<void*>(m_addr & ~(pageSize() - 1));
        }

    public:
        explicit Addr(void* ptr) : m_addr(reinterpret_cast<uintptr_t>(ptr)) {}
        explicit Addr(uintptr_t addr) : m_addr(addr) {}
        template<size_t bit>
        explicit Addr(const PtrLow<bit>& obj) : Addr(obj.value()) {}

        bool pageAligned() const {
            return (m_addr % pageSize()) == 0;
        }

        bool setProtection(int prot) const {
            if (!m_addr) return false;
            if (mprotect(pageStart(), pageSize(), prot) != 0) {
                perror("mprotect failed");
                return false;
            }
            return true;
        }

        bool write(const void* buffer, std::size_t length) const {
            if (!m_addr || !buffer || length == 0) return false;

            if (!setProtection(PROT_READ | PROT_WRITE | PROT_EXEC)) {
                return false;
            }

            std::memcpy(ptr(), buffer, length);
            return true;
        }

        bool read(void* buffer, std::size_t length) const {
            if (!m_addr || !buffer || length == 0) return false;

            if (!setProtection(PROT_READ | PROT_WRITE | PROT_EXEC)) {
                return false;
            }

            std::memcpy(buffer, ptr(), length);
            return true;
        }

        template<typename _Ty, std::size_t _Sz = sizeof(_Ty)> // NOLINT(*-reserved-identifier)
        bool writeType(const _Ty& value) const {
            return write(&value, _Sz);
        }

        template<typename _Ty, std::size_t _Sz = sizeof(_Ty)> // NOLINT(*-reserved-identifier)
        _Ty readType() const {
            _Ty result{};
            read(reinterpret_cast<void*>(&result), _Sz);
            return result;
        }

        template<typename _Ty, std::size_t _Sz = sizeof(_Ty)> // NOLINT(*-reserved-identifier)
        bool readType(_Ty* value) const {
            return read(reinterpret_cast<void*>(value), _Sz);
        }

        uintptr_t address() const {
            return m_addr;
        }

        void* ptr() const {
            return reinterpret_cast<void*>(m_addr);
        }

        operator uintptr_t() const {
            return address();
        }

        Addr alignUp(uintptr_t alignment) const {
            return Addr((m_addr + alignment - 1) & ~(alignment - 1));
        }
        Addr alignDown(uintptr_t alignment) const {
            return Addr(m_addr & ~(alignment - 1));
        }
        Addr offset(ptrdiff_t off) const {
            return Addr(m_addr + off);
        }
        Addr operator+(uintptr_t offset) const {
            return Addr(m_addr + offset);
        }
        Addr operator-(uintptr_t offset) const {
            return Addr(m_addr - offset);
        }
        Addr& operator+=(uintptr_t offset) {
            m_addr += offset;
            return *this;
        }
        Addr& operator-=(uintptr_t offset) {
            m_addr -= offset;
            return *this;
        }
        Addr operator&(uintptr_t mask) const { return Addr(m_addr & mask); }
        Addr operator|(uintptr_t mask) const { return Addr(m_addr | mask); }
        Addr operator^(uintptr_t mask) const { return Addr(m_addr ^ mask); }
        Addr& operator&=(uintptr_t mask) {
            m_addr &= mask;
            return *this;
        }
        Addr& operator|=(uintptr_t mask) {
            m_addr |= mask;
            return *this;
        }
        Addr& operator^=(uintptr_t mask) {
            m_addr ^= mask;
            return *this;
        }

        Addr operator<<(unsigned shift) const {
            return Addr(m_addr << shift);
        }
        Addr operator>>(unsigned shift) const {
            return Addr(m_addr >> shift);
        }
        Addr& operator<<=(unsigned shift) {
            m_addr <<= shift;
            return *this;
        }
        Addr& operator>>=(unsigned shift) {
            m_addr >>= shift;
            return *this;
        }

        bool operator==(const Addr& other) const { return m_addr == other.m_addr; }
        bool operator!=(const Addr& other) const { return m_addr != other.m_addr; }
        bool operator<(const Addr& other) const { return m_addr < other.m_addr; }
        bool operator>(const Addr& other) const { return m_addr > other.m_addr; }

        operator bool() const { return m_addr != 0; }
    };

    class Module {
    public:
        std::string name;
        uintptr_t start = 0;
        uintptr_t end = 0;

        explicit Module(std::string name_ = "", uintptr_t start_ = 0, uintptr_t end_ = 0)
            : name(std::move(name_)), start(start_), end(end_) {}

        ~Module() = default;

        bool hasValue() const {
            return start && end;
        }

        static Module Read(const std::string& name, int index) {
            std::ifstream maps("/proc/self/maps");
            if (!maps.is_open()) return Module(name);

            std::string line;
            int count = 0;
            while (std::getline(maps, line)) {
                if (line.find(name) != std::string::npos) {
                    count++;
                    if (count == index) {
                        std::istringstream iss(line);
                        std::string addr_range;
                        if (iss >> addr_range) {
                            size_t dash = addr_range.find('-');
                            if (dash != std::string::npos) {
                                uintptr_t start = std::stoull(addr_range.substr(0, dash), nullptr, 16);
                                uintptr_t end = std::stoull(addr_range.substr(dash + 1), nullptr, 16);
                                return Module(name, start, end);
                            }
                        }
                    }
                }
            }
            return Module(name);
        }
    };

    static bool IsPtrValid(void* addr, size_t size = 1) {
        if (!addr) return false;

        auto start = reinterpret_cast<uintptr_t>(addr);
        auto end = start + size;

        static const size_t PAGE_SIZE = sysconf(_SC_PAGESIZE);

        for (uintptr_t page = start & ~(PAGE_SIZE - 1); page < end; page += PAGE_SIZE) {
            unsigned char vec;
            int ret = mincore(reinterpret_cast<void*>(page), PAGE_SIZE, &vec);
            if (ret != 0 || (vec & 1) == 0) {
                return false;
            }
        }
        return true;
    }

    static bool IsSafeAddress(uintptr_t addr, size_t size) {
        if (addr <= 0x10000000 || addr >= 0x10000000000) return false;
        return IsPtrValid(reinterpret_cast<void*>(addr), size);
    }
}

#endif //MEMORYTOOLSCPP_HPP
