#include "common.h"
#include "statistics_common.h"
#include "color_print.h"
#include "Connection.h"

GlobStats globStats;

ullint_t GlobStats::totNumBytes;
map<const long, int> GlobStats::byteLatencyVariationCDFValues;

/*****************************************
 * LatencyItem
 *****************************************/
csv::ofstream& operator<<(csv::ofstream& stream, LatencyItem& lat) {
	stream << lat.time_ms << lat.latency << lat.stream_id;
	return stream;
}

void update_vectors_size(vector<SPNS::shared_ptr<vector <LatencyItem> > > &vectors, ulong count) {
	for (ulong i = vectors.size(); i < count; i++) {
		vectors.push_back(SPNS::shared_ptr<vector <LatencyItem> > (new vector<LatencyItem>()));
	}
}

/*****************************************
 * PacketStats
 *****************************************/
void PacketStats::writeHeader(csv::ofstream& stream) {
	stream << "stream_id"
		   << "time"
		   << "itt"
		   << "payload_bytes"
		   << NEWLINE;
}

csv::ofstream& operator<<(csv::ofstream& stream, PacketStats& s) {
	stream << s.stream_id
		   << s.send_time_us
		   << s.itt
		   << s.size
		   << NEWLINE;
	return stream;
}

/*****************************************
 * SegmentStats
 *****************************************/
void SegmentStats::writeHeader(csv::ofstream& stream) {
	stream << "stream_id"
		   << "time"
		   << "payload_bytes"
		   << "sojourn_time"
		   << "ack_latency"
		   << "sojourn_and_ack_latency"
		   << NEWLINE;
}

csv::ofstream& operator<<(csv::ofstream& stream, SegmentStats& s) {
	if (s.s_type == ST_PKT) {
		for (ulong i = 0; i < s.sojourn_times.size(); i++) {
			stream << s.stream_id
				   << s.send_time_us
				   << s.sojourn_times[i].first
				   << s.sojourn_times[i].second
				   << s.ack_latency_usec
				   << s.sojourn_times[i].second + s.ack_latency_usec
				   << NEWLINE;
		}
	}
	return stream;
}

/*****************************************
 * ConnCSVItem
 *****************************************/

void ConnCSVItem::writeHeader(csv::ofstream& csv) {
	csv << "stream_id"
		<< "Total packets sent (adj)"
		<< "Total packets sent (dump)"
		<< "Total data packets sent (adj)"
		<< "Total data packets sent (dump)"
		<< "Total pure acks (no payload)"
		<< "SYN packets sent"
		<< "FIN packets sent"
		<< "RST packets sent"
		<< "Number of retransmissions"
		<< "Number of packets with bundled segments"
		<< "Number of packets with redundant data"
		<< "Number of received acks"
		<< "Total bytes sent (payload)"
		<< "Number of unique bytes"
		<< "Number of retransmitted bytes"
		<< "Redundant bytes (bytes already sent)"
		<< "Estimated loss rate based on retransmission"
		<< "Based on sent pkts (adj)"
		<< "Based on sent pkts (dump)"
		<< NEWLINE;
}


csv::ofstream& operator<<(csv::ofstream& os, ConnCSVItem& val)
{
	os << val.conn->getConnKey()
	   << val.conn->getDuration(true)
	   << val.cs->nrPacketsSent
	   << val.cs->nrPacketsSentFoundInDump
	   << val.cs->nrDataPacketsSent
	   << val.cs->nrDataPacketsSent - (val.cs->nrPacketsSent - val.cs->nrPacketsSentFoundInDump)
	   << val.cs->pureAcksCount
	   << val.cs->synCount
	   << val.cs->finCount
	   << val.cs->rstCount
	   << val.cs->nrRetrans
	   << val.cs->bundleCount
	   << val.cs->nrRetrans - val.cs->nrRetransNoPayload + val.cs->bundleCount
	   << val.cs->ackCount
	   << val.cs->totBytesSent
	   << val.cs->totUniqueBytesSent
	   << val.cs->totRetransBytesSent
	   << val.cs->totBytesSent - val.cs->totUniqueBytesSent
	   << safe_div((val.cs->totBytesSent - val.cs->totUniqueBytesSent), val.cs->totBytesSent) * 100
	   << NEWLINE;
	return os;
}


/*****************************************
 * LossInterval
 *****************************************/
void LossInterval::writeHeader(csv::ofstream& stream) {
	stream << "interval"
		   << "ranges_sent"
		   << "all_bytes_sent"
		   << "old_bytes_sent"
		   << "new_bytes_sent"
		   << "ranges_lost"
		   << "all_bytes_lost"
		   << "old_bytes_lost"
		   << "new_bytes_lost"
		   << "ranges_lost_relative_to_interval"
		   << "all_bytes_lost_relative_to_interval"
		   << "old_bytes_lost_relative_to_interval"
		   << "new_bytes_lost_relative_to_interval"
		   << "old_bytes_lost_relative_to_all_bytes_lost"
		   << "new_bytes_lost_relative_to_all_bytes_lost"
		   << "ranges_lost_relative_to_total"
		   << "all_bytes_lost_relative_to_total"
		   << NEWLINE;
}

csv::ofstream& operator<<(csv::ofstream& s, LossInterval& v) {
	// total sent during interval
	s << v.tot_cnt_bytes;
	s << v.tot_all_bytes;
	s << (v.tot_all_bytes - v.tot_new_bytes);
	s << v.tot_new_bytes;

	// total lost during interval
	s << v.cnt_bytes;
	s << v.all_bytes;
	s << (v.all_bytes - v.new_bytes);
	s << v.new_bytes;

	// total lost relative to sent within interval
	if (v.tot_cnt_bytes != 0)
		s << (v.cnt_bytes / v.tot_cnt_bytes);
	else
		s << 0;

	if (v.tot_all_bytes != 0)
		s << (v.all_bytes / v.tot_all_bytes);
	else
		s << 0;

	if ((v.tot_all_bytes - v.tot_new_bytes) != 0)
		s << ((v.all_bytes - v.new_bytes) / (v.tot_all_bytes - v.tot_new_bytes));
	else
		s << 0;

	if (v.tot_new_bytes != 0)
		s << (v.new_bytes / v.tot_new_bytes);
	else
		s << 0;

	// total lost relative to lost within interval
	if (v.all_bytes != 0)
		s << ((v.all_bytes - v.new_bytes) / v.all_bytes);
	else
		s << 0;

	if (v.all_bytes != 0)
		s << (v.new_bytes / v.all_bytes);
	else
		s << 0;

	return s;
}


 /*****************************************
  * Percentiles
  *****************************************/
 void Percentiles::init()
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

 void Percentiles::compute(const vector<double>& v)
 {
 	double num;
     auto it  = percentiles.begin();
     auto end = percentiles.end();
     for (; it!=end; it++)
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
     , _counter(0)
     , valid(true)
 {init();}

 void BaseStats::init() {
     min = std::numeric_limits<uint64_t>::max();
     max = 0;
     cum = 0;
     _counter = 0;
	 _percentiles.init();
	 _values.clear();
 }

 void BaseStats::add(ullint_t val)
 {
     assert(_is_aggregate == false);
     assert(valid);
     _counter++;
     this->min = std::min<ullint_t>(this->min, val);
     this->max = std::max<ullint_t>(this->max, val);
     this->cum += val;
	 _values.push_back(val);
 }

 double BaseStats::get_avg() const
 {
     if (_counter == 0) return 0;
     return (double) cum / (double) _counter;
 }

 uint32_t BaseStats::get_counter() const
 {
     return _counter;
 }

 void BaseStats::add_to_aggregate(const BaseStats &rhs)
 {
     assert(_is_aggregate == true);
     assert(valid);
     if (!rhs.valid)
     {
         cerr << "WARNING: rhs is invalid in " << __FILE__ << ":" << __LINE__ << endl;
         return;
     }
     this->min = std::min<int64_t>(this->min, rhs.min);
     this->max = std::max<int64_t>(this->max, rhs.max);
     this->cum += rhs.cum;
	 _values.insert(_values.end(), rhs._values.begin(), rhs._values.end());
     _counter += rhs._values.size();
 }

void BaseStats::makeStats()
{
    if (_values.size())
    {
        if (_values.size() != BaseStats::get_counter())
        {
            cerr << "Crashing !" << endl
                 << "Array size: " << _values.size() << endl
                 << "Counter:    " << BaseStats::get_counter() << endl;
            assert(_values.size() == BaseStats::get_counter());
        }

        double mean   = BaseStats::get_avg();
        double temp   = 0;

        auto it  = _values.begin();
        auto end = _values.end();
        for (; it!=end; it++)
        {
            double val = (*it) - mean;
            temp += val * val;
        }
        _std_dev = sqrt(temp / BaseStats::get_counter());

        std::sort(_values.begin(), _values.end());
        _percentiles.compute(_values);
    }
    else
    {
        BaseStats::valid = false;
    }
}

void BaseStats::sortValues()
{
    std::sort(_values.begin(), _values.end());
}

void BaseStats::computePercentiles()
{
    _percentiles.compute(_values);
}

 /*****************************************
  * AggrPacketsStats
  *****************************************/
 void AggrPacketsStats::add(PacketsStats &bs)
 {
	if (bs.latency.get_counter()) {
		aggregated.latency.add_to_aggregate(bs.latency);
		average.latency.add(bs.latency.get_avg());
		minimum.latency.add(bs.latency.min);
		maximum.latency.add(bs.latency.max);
	}

	if (bs.packet_length.get_counter()) {
		aggregated.packet_length.add_to_aggregate(bs.packet_length);
		average.packet_length.add(bs.packet_length.get_avg());
		minimum.packet_length.add(bs.packet_length.min);
		maximum.packet_length.add(bs.packet_length.max);
	}

	if (bs.itt.get_counter()) {
		aggregated.itt.add_to_aggregate(bs.itt);
		average.itt.add(bs.itt.get_avg());
		minimum.itt.add(bs.itt.min);
		maximum.itt.add(bs.itt.max);
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
