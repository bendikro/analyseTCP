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

#include "fourTuple.h"
// #include "common.h"
// #include <getopt.h>
// #include <sys/stat.h>
// #include <arpa/inet.h>
#include <sstream>
#include <iostream>
// #include <stdio.h>
#include <string.h>

#ifdef OS_FREEBSD
#include <sys/socket.h>
#endif

using namespace std;

string four_tuple_t::to_string( ) const
{
    ostringstream ostr;
    ostr << addr_to_string(_ip_left) << ":" << _port_left << "-";
    ostr << addr_to_string(_ip_right) << ":" << _port_right;
    return ostr.str();
}

string four_tuple_t::addr_to_string( in_addr_t addr )
{
    ostringstream ostr;
    char buf[16];
    ostr << inet_ntop( AF_INET, &addr, buf, 16 );
    return ostr.str();
}

std::string four_tuple_t::port_to_string( uint16_t port )
{
    ostringstream ostr;
    ostr << port;
    return ostr.str();
}

four_tuple_t::four_tuple_t( const char* arg )
    : _valid( false )
{
    char *arg_copy = strdup( arg );
    char *connection = arg_copy;
    char *str;

    str = strsep( &connection, ":" );
    if( str != 0 )
    {
        _ip_left = inet_addr( str );
        str = strsep( &connection, "-" );
        if( str != 0 )
        {
            _port_left = strtol( str, 0, 10 );
            str = strsep( &connection, ":" );
            if( str != 0 )
            {
                _ip_right = inet_addr( str );
                if( connection )
                {
                    _port_right = strtol( connection, 0, 10 );
                    cerr << "Parsed connection " << to_string() << endl;
                    _valid = true;
                }
            }
        }
    }
    free( arg_copy );
}

