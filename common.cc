#include <assert.h>
#include <algorithm>

#include "common.h"

vector<string> GlobStats::retrans_filenames;
vector<std::tr1::shared_ptr<vector <LatencyItem> > > GlobStats::ack_latency_vectors;
GlobStats *globStats;

/* Initialize global options */
bool GlobOpts::aggregate          		= false;
bool GlobOpts::aggOnly            		= false;
bool GlobOpts::withRecv           		= false;
bool GlobOpts::withLoss           		= false;
bool GlobOpts::withCDF            		= false;
bool GlobOpts::transport          		= false;
bool GlobOpts::genAckLatencyFiles 		= false;
bool GlobOpts::withThroughput			= false;
string GlobOpts::prefix           		= "";
string GlobOpts::RFiles_dir       		= "";
int GlobOpts::debugLevel          		= 0;
uint64_t GlobOpts::lossAggrMs     		= 1000;
uint64_t GlobOpts::throughputAggrMs 	= 1000;
bool GlobOpts::relative_seq       		= false;
bool GlobOpts::print_packets      		= false;
vector <pair<uint64_t, uint64_t> > GlobOpts::print_packets_pairs;
string GlobOpts::sendNatIP        		= "";
string GlobOpts::recvNatIP        		= "";
bool GlobOpts::connDetails        		= false;
int GlobOpts::verbose             		= 0;
bool GlobOpts::validate_ranges    		= true;
int GlobOpts::max_retrans_stats   		= 6;
string GlobOpts::percentiles      		= "";
int GlobOpts::analyse_start       		= 0;
int GlobOpts::analyse_end         		= 0;
int GlobOpts::analyse_duration    		= 0;
bool GlobOpts::oneway_delay_variance	= false;

bool operator==(const timeval& lhs, const timeval& rhs) {
	return lhs.tv_sec == rhs.tv_sec && lhs.tv_usec == rhs.tv_usec;
}

void warn_with_file_and_linenum(string file, int linenum) {
	cout << "Error at ";
	cout << "File: " << file << " Line: " << linenum  << endl;
}

void exit_with_file_and_linenum(int exit_code, string file, int linenum) {
	warn_with_file_and_linenum(file, linenum);
	exit(exit_code);
}

bool endsWith(const string& s, const string& suffix) {
	return s.rfind(suffix) == (s.size()-suffix.size());
}

/*****************************************
 * LatencyItem
 *****************************************/
string LatencyItem::str() const {
	ostringstream buffer;
	buffer << time_ms << "," << latency;
	return buffer.str();
}

ofstream& operator<<(ofstream& stream, const LatencyItem& lat) {
	stream << lat.str();
	return stream;
}

/*****************************************
 * Percentiles
 *****************************************/
void Percentiles::init( )
{
	max_char_length = 0;
	std::istringstream ss(GlobOpts::percentiles);
	std::string token;
	double num;
    while (std::getline(ss, token, ','))
    {
		istringstream(token) >> num;
		if (num >= 100) {
			colored_printf(YELLOW, "Invalid percentile '%s'\n", token.c_str());
			continue;
		}
		max_char_length = token.length();
		percentiles.insert(pair<string, double>(token, 0));
    }
}

void Percentiles::compute( const vector<double>& v )
{
	double num;
    auto it  = percentiles.begin();
    auto end = percentiles.end();
    for( ; it!=end; it++ )
    {
		istringstream(it->first) >> num;
		vector<double>::const_iterator it_p = v.begin() + ((int) ceil(v.size() * (num / 100.0)));
		it->second = *it_p;
	}
}

void Percentiles::print(string fmt, bool show_quartiles)
{
	map<string, double>::iterator it;
	for (it = percentiles.begin(); it != percentiles.end(); it++) {
		if (show_quartiles) {
			string q = "";
			if (it->first == "25")
				q = "(First quartile)";
			else if (it->first == "50")
				q = "(Second quartile, median) ";
			else if (it->first == "75")
				q = "(Third quartile)";
			printf(fmt.c_str(), max_char_length, it->first.c_str(), q.c_str(), it->second);
		}
		else
			printf(fmt.c_str(), max_char_length, it->first.c_str(), it->second);
	}
}

/*****************************************
 * BaseStats
 *****************************************/
BaseStats::BaseStats( bool is_aggregate )
    : _is_aggregate( is_aggregate )
    , _counter( 0 )
    , min( std::numeric_limits<int64_t>::max() )
    , max(0)
    , cum(0)
    , valid( true )
{
}

void BaseStats::add_to_aggregate( const BaseStats &rhs )
{
    assert( _is_aggregate );
    assert( valid );
    if( not rhs.valid )
    {
        cerr << "WARNING: rhs is invalid in " << __FILE__ << ":" << __LINE__ << endl;
        return;
    }

    _counter++;
    this->min = std::min<int64_t>( this->min, rhs.min );
    this->max = std::max<int64_t>( this->max, rhs.max );
    this->cum += rhs.cum;
}

void BaseStats::add( uint64_t val )
{
    assert( not _is_aggregate );
    assert( valid );
    _counter++;
    this->min = std::min<int64_t>( this->min, val );
    this->max = std::max<int64_t>( this->max, val );
    this->cum += val;
}

double BaseStats::get_avg( ) const
{
    if( _counter == 0 ) return 0;
    return (double)cum/(double)_counter;
}

uint32_t BaseStats::get_counter( ) const
{
    return _counter;
}

#ifdef EXTENDED_STATS
/*****************************************
 * ExtendedStats
 *****************************************/
void ExtendedStats::add_to_aggregate( const ExtendedStats &rhs )
{
    BaseStats::add_to_aggregate( rhs );
    _values.insert( _values.end(), rhs._values.begin(), rhs._values.end() );
}

void ExtendedStats::add( uint64_t val )
{
    BaseStats::add( val );
    _values.push_back( val );
}

void ExtendedStats::makeStats( )
{
    if( _values.size() )
    {
        if( _values.size() != BaseStats::get_counter() )
        {
            cerr << "Crashing !" << endl
                 << "Array size: " << _values.size() << endl
                 << "Counter:    " << BaseStats::get_counter() << endl;
            assert( _values.size() == BaseStats::get_counter() );
        }

        // double sumLat = BaseStats::cum;
        double mean   = BaseStats::get_avg();
        double temp   = 0;

        auto it  = _values.begin();
        auto end = _values.end();
        for( ; it!=end; it++ )
        {
            double val = (*it) - mean;
            temp += val * val;
        }
        _std_dev = sqrt( temp / BaseStats::get_counter() );

        std::sort( _values.begin(), _values.end() );

        _percentiles.compute( _values );
        // percentiles( _values, _percentiles );
    }
    else
    {
        BaseStats::valid = false;
    }
}

void ExtendedStats::sortValues( )
{
    std::sort( _values.begin(), _values.end() );
}

void ExtendedStats::computePercentiles( )
{
    _percentiles.compute( _values );
}

#endif

