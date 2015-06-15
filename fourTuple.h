#pragma once

/*************************************************************************************
**************************************************************************************
**                                                                                  **
**  analyseDASH - Tool for analysing sets of tcpdumps to understand how DASH flows  **
**                behave per segment.                                               **
**                                                                                  **
**  Copyright (C) 2007     Andreas Petlund  - andreas@petlund.no                    **
**                     and Kristian Evensen - kristrev@ifi.uio.no                   **
**                2015     Carsten Griwodz  - griff@simula.no                       **
**                                                                                  **
**     This program is free software; you can redistribute it and/or modify         **
**     it under the terms of the GNU General Public License as published by         **
**     the Free Software Foundation; either version 2 of the License, or            **
**     (at your option) any later version.                                          **
**                                                                                  **
**     This program is distributed in the hope that it will be useful,              **
**     but WITHOUT ANY WARRANTY; without even the implied warranty of               **
**     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                **
**     GNU General Public License for more details.                                 **
**                                                                                  **
**     You should have received a copy of the GNU General Public License along      **
**     with this program; if not, write to the Free Software Foundation, Inc.,      **
**     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.                  **
**                                                                                  **
**************************************************************************************
*************************************************************************************/

#include <string>
#include <arpa/inet.h>
#include <stdint.h>

class four_tuple_t
{
    in_addr_t _ip_left;
    in_addr_t _ip_right;
    uint16_t  _port_left;
    uint16_t  _port_right;
    bool      _valid;

public:
    four_tuple_t( const char* arg );

    bool valid() const { return _valid; }

    std::string ip_left() const    { return addr_to_string( _ip_left ); }
    std::string ip_right() const   { return addr_to_string( _ip_right ); }
    std::string port_left() const  { return port_to_string( _port_left ); }
    std::string port_right() const { return port_to_string( _port_right ); }

    std::string to_string( ) const;

private:
    static std::string addr_to_string( in_addr_t addr );
    static std::string port_to_string( uint16_t port );
};

