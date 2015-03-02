#include "common.h"
#include "statistics_common.h"
#include "color_print.h"

GlobStats globStats;

uint64_t GlobStats::totNumBytes;
map<const long, int> GlobStats::byteLatencyVariationCDFValues;

/*****************************************
 * LatencyItem
 *****************************************/
string LatencyItem::str() const {
	ostringstream buffer;
	buffer << time_ms << "," << latency << "," << stream_id;
	return buffer.str();
}

 ofstream& operator<<(ofstream& stream, const LatencyItem& lat) {
 	stream << lat.str();
 	return stream;
 }

void update_vectors_size(vector<SPNS::shared_ptr<vector <LatencyItem> > > &vectors, ulong count) {
	for (ulong i = vectors.size(); i < count; i++) {
		vectors.push_back(SPNS::shared_ptr<vector <LatencyItem> > (new vector<LatencyItem>()));
	}
}

 /*
  * Output a loss interval value to an output file stream
  */
 ofstream& operator<<(ofstream& s, const LossInterval& v) {
 	// total sent during interval
 	s << v.tot_cnt_bytes << ",";
 	s << v.tot_all_bytes << ",";
 	s << (v.tot_all_bytes - v.tot_new_bytes) << ",";
 	s << v.tot_new_bytes << ",";

 	// total lost during interval
 	s << v.cnt_bytes << ",";
     s << v.all_bytes << ",";
 	s << (v.all_bytes - v.new_bytes) << ",";
 	s << v.new_bytes << ",";

 	// total lost relative to sent within interval
 	if (v.tot_cnt_bytes != 0)
 		s << (v.cnt_bytes / v.tot_cnt_bytes) << ",";
 	else
 		s << 0 << ",";

 	if (v.tot_all_bytes != 0)
 		s << (v.all_bytes / v.tot_all_bytes) << ",";
 	else
 		s << 0 << ",";

 	if ((v.tot_all_bytes - v.tot_new_bytes) != 0)
 		s << ((v.all_bytes - v.new_bytes) / (v.tot_all_bytes - v.tot_new_bytes)) << ",";
 	else
 		s << 0 << ",";

 	if (v.tot_new_bytes != 0)
 		s << (v.new_bytes / v.tot_new_bytes) << ",";
 	else
 		s << 0 << ",";

 	// total lost relative to lost within interval
 	if (v.all_bytes != 0)
 		s << ((v.all_bytes - v.new_bytes) / v.all_bytes) << ",";
 	else
 		s << 0 << ",";

 	if (v.all_bytes != 0)
 		s << (v.new_bytes / v.all_bytes);
 	else
 		s << 0;

 	return s;
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
 	if (!percentiles.size())
 		return;

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
 BaseStats::BaseStats(bool is_aggregate)
     : _is_aggregate(is_aggregate)
     , _counter( 0 )
     , min( std::numeric_limits<int64_t>::max() )
     , max(0)
     , cum(0)
     , valid( true )
 {}

 void BaseStats::add( uint64_t val )
 {
     assert( _is_aggregate == false );
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

 void BaseStats::add_to_aggregate(const BaseStats &rhs)
 {
     assert( _is_aggregate == true );
     assert( valid );
     if( not rhs.valid )
     {
         cerr << "WARNING: rhs is invalid in " << __FILE__ << ":" << __LINE__ << endl;
         return;
     }
     this->min = std::min<int64_t>( this->min, rhs.min );
     this->max = std::max<int64_t>( this->max, rhs.max );
     this->cum += rhs.cum;
     _counter++;
 }

 /*****************************************
  * AggrPacketStats
  *****************************************/
 void AggrPacketStats::add(PacketStats &bs)
 {
 	int64_t max_value = (numeric_limits<int64_t>::max)();

 	aggregated.latency.add_to_aggregate(bs.latency);
 	average.latency.add(bs.latency.get_avg());
 	minimum.latency.add(bs.latency.min);
 	maximum.latency.add(bs.latency.max);

 	aggregated.packet_length.add_to_aggregate(bs.packet_length);
 	average.packet_length.add(bs.packet_length.get_avg());
 	minimum.packet_length.add(bs.packet_length.min);
 	maximum.packet_length.add(bs.packet_length.max);

 	aggregated.itt.add_to_aggregate(bs.itt);
 	average.itt.add(bs.itt.get_avg());
 	minimum.itt.add(bs.itt.min);
 	maximum.itt.add(bs.itt.max);

 	if (bs.itt.min == max_value) {
 		fprintf(stderr, "ERROR!!\n");
 	}

 	// Add retrans stats
 	if ((ulong) bs.retrans.size() > aggregated.retrans.size()) {
 		for (ulong i = aggregated.retrans.size(); i < bs.retrans.size(); i++) {
 			aggregated.retrans.push_back(0);
 		}
	}

	for (ulong i = 0; i < bs.retrans.size(); i++) {
		aggregated.retrans[i] += bs.retrans[i];
	}

	// Add dupack stats
	if ((ulong) bs.dupacks.size() > aggregated.dupacks.size()) {
		for (ulong i = aggregated.dupacks.size(); i < bs.dupacks.size(); i++) {
			aggregated.dupacks.push_back(0);
		}
	}

	for (ulong i = 0; i < bs.dupacks.size(); i++) {
		aggregated.dupacks[i] += bs.dupacks[i];
	}
}


/*****************************************
 * ExtendedStats
 *****************************************/
void ExtendedStats::add_to_aggregate
( const ExtendedStats &rhs )
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
