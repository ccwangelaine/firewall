import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class Main
{
    public static void main(String[] args) {

        FireWall fireWall = new FireWall("/Users/elaine/Documents/FireWall/firewall_test.csv");
        boolean result = fireWall.accept_packet("inbound", "tcp", 25, "100.0.2.0");
        System.out.println(result);
        boolean result2 = fireWall.accept_packet("outbound", "tcp", 30, "100.3.4.2");
        System.out.println(result2);
        boolean result3 = fireWall.accept_packet("inbound", "udp", 20, "120.4.5.6");
        System.out.println(result3);
        boolean result4 = fireWall.accept_packet("inbound", "udp", 20, "120.4.5.7");
        System.out.println(result4);
        boolean result5 = fireWall.accept_packet("outbound", "tcp", 30, "100.0.3.3");
        System.out.println(result5);
        /* investigate unexpected ouctome" */
        boolean result6 = fireWall.accept_packet("outbound", "udp", 20, "199.2.3.4");
        System.out.println(result6);


    }
}

class FireWall {
    RuleSet _ruleSet;

    public FireWall(String csvFilePath) {
        _ruleSet = new RuleSet();
        try {
            BufferedReader csvReader = new BufferedReader (new FileReader(csvFilePath));
            String row;
            while ((row = csvReader.readLine()) != null) {
                String[] data = row.split(",");

                for (int i = 0; i < data.length; i++) {
                    data[i] = data[i].replaceAll("[\uFEFF-\uFFFF]", "");
                }

                /* check if port has range */
                PortRangePair portRangePair;
                if (data[2].contains("-")) {
                    int idx = data[2].indexOf("-");
                    int lower = Integer.parseInt(data[2].substring(0, idx));
                    int upper = Integer.parseInt(data[2].substring(idx+1));
                    portRangePair = new PortRangePair(lower, upper);
                } else {
                    int lower = Integer.parseInt(data[2]);
                    portRangePair = new PortRangePair(lower);
                }

                /* check if ip address has range */
                IPRangePair ipRangePair;
                if (data[3].contains("-")) {
                    int idx = data[3].indexOf("-");
                    String lowerString = data[3].substring(0, idx);
                    String[] lowerAddressString = lowerString.split("\\.");
                    int[] lowerAddress = new int[4];
                    for (int i = 0; i < 4; i++) {
                        lowerAddress[i] = Integer.parseInt(lowerAddressString[i]);
                    }

                    String upperString = data[3].substring(idx+1);
                    String[] upperAddressString = upperString.split("\\.");
                    int[] upperAddress = new int[4];
                    for (int i = 0; i < 4; i++) {
                        upperAddress[i] = Integer.parseInt(upperAddressString[i]);
                    }

                    ipRangePair = new IPRangePair(lowerAddress, upperAddress);
                } else {
                    String[] lowerAddressString = data[3].split("\\.");
                    int[] lowerAddress = new int[4];
                    for (int i = 0; i < 4; i++) {
                        lowerAddress[i] = Integer.parseInt(lowerAddressString[i]);
                    }

                    ipRangePair = new IPRangePair(lowerAddress);
                }
                Record rec =  new Record(data[0], data[1], portRangePair, ipRangePair);
                _ruleSet.addRule(rec);
            }
            csvReader.close();
        } catch (FileNotFoundException ex) {
            System.out.println("csv file not found");
        } catch (IOException ex2) {
            System.out.println("io exception");
        }
    }

    boolean accept_packet(String direction, String protocol, int port, String ip_address) {
        String[] ip_address_array = ip_address.split("\\.");
        int[] ip_nums = new int[4];
        for (int i = 0; i < 4; i++) {
            ip_nums[i] = Integer.parseInt(ip_address_array[i]);
        }

        Record rec = new Record(direction, protocol, new PortRangePair(port), new IPRangePair(ip_nums));
        return _ruleSet.inRule(rec);
    }
}

// An IPAddress can be represented as an array for 4 integers
class IPRangePair {
    boolean _isRange;
    int[]   _lowerAddress;
    int[]   _upperAddress;

    public IPRangePair(IPRangePair pair) {
        _isRange = pair.isRange();
        if (_isRange) {
            _lowerAddress = new int[4];
            _upperAddress = new int[4];
            int[] lowerAddress = pair.getLowerAddress();
            int[] upperAddress = pair.getUpperAddress();
            for (int i = 0; i < _lowerAddress.length; i++) {
                _lowerAddress[i] = lowerAddress[i];
                _upperAddress[i] = upperAddress[i];
            }
        } else {
            _lowerAddress = new int[4];
            int[] lowerAddress = pair.getLowerAddress();
            for (int i = 0; i < _lowerAddress.length; i++) {
                _lowerAddress[i] = lowerAddress[i];
            }
        }
    }

    public IPRangePair(int[] lowerAddress, int[] upperAddress) {
        _isRange = true;
        _lowerAddress = new int[4];
        _upperAddress = new int[4];
        for (int i = 0; i < _lowerAddress.length; i++) {
            _lowerAddress[i] = lowerAddress[i];
            _upperAddress[i] = upperAddress[i];
        }
    }

    public IPRangePair(int[] lowerAddress) {
        _isRange = false;
        _lowerAddress = new int[4];
        for (int i = 0; i < lowerAddress.length; i++) {
            _lowerAddress[i] = lowerAddress[i];
        }
    }

    public boolean isRange() {
        return _isRange;
    }

    public int[] getLowerAddress() {
        return _lowerAddress;
    }

    public int[] getUpperAddress() {
        return _upperAddress;
    }

    int genAddressNumber(int [] address) {
        return (address[0] << 24) + (address[1] << 16) + (address[2] << 8) + (address[3]);
    }

    public boolean covers(int[] address) {
        if (_isRange) {
            int lower = genAddressNumber(_lowerAddress);
            int upper = genAddressNumber(_upperAddress);
            int num   = genAddressNumber(address);
            return (lower <= num) && (num <= upper);
        } else {
            int lower = genAddressNumber(_lowerAddress);
            int num   = genAddressNumber(address);
            return lower == num;
        }
    }

    @Override
    public int hashCode() {
        if (_isRange) {
            return 0;
        } else {
            return Arrays.hashCode(_lowerAddress);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (this.getClass() != o.getClass()) return false;
        IPRangePair ipRangePair = (IPRangePair) o;
        if (ipRangePair.isRange() != _isRange) return false;
        if (_isRange) {
            int[] lowerAddress = ipRangePair.getLowerAddress();
            int[] upperAddress = ipRangePair.getUpperAddress();
            for (int i = 0; i < _lowerAddress.length; i++) {
                if (_lowerAddress[i] == lowerAddress[i] && _upperAddress[i] == upperAddress[i]) {
                    /* up to now is equal, then continue; */
                    continue;
                } else {
                    /* inconsistent; then return false; */
                    return false;
                }
            }
        } else {
            int[] lowerAddress = ipRangePair.getLowerAddress();
            for (int i = 0; i < _lowerAddress.length; i++) {
                if (_lowerAddress[i] == lowerAddress[i]) {
                    /* up to now is equal, then continue; */
                    continue;
                } else {
                    /* inconsistent; then return false; */
                    return false;
                }
            }
        }
        /* everything is contained, then return true; */
        return true;
    }
}

class PortRangePair {
    boolean _isRange;
    int     _lowerNum;
    int     _upperNum;

    public PortRangePair(PortRangePair pair) {
        _isRange  = pair.isRange();
        _lowerNum = pair.getLowerNum();
        _upperNum = pair.getUpperNum();
    }

    public PortRangePair(int lower, int upper) {
        _isRange  = true;
        _lowerNum = lower;
        _upperNum = upper;
    }

    public PortRangePair(int lower) {
        _isRange = false;
        _lowerNum = lower;
    }

    public boolean isRange() {
        return _isRange;
    }

    public int getLowerNum() {
        return _lowerNum;
    }

    public int getUpperNum() {
        return _upperNum;
    }

    public boolean covers(int num) {
        if (_isRange) {
            return (_lowerNum <= num) && (num <= _upperNum);
        } else {
            return _lowerNum == num;
        }
    }

    @Override
    public int hashCode() {
        if (_isRange) {
            return 0;
        } else {
            return _lowerNum;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (this.getClass() != o.getClass()) return false;
        PortRangePair portRangePair = (PortRangePair) o;
        if (_isRange != portRangePair.isRange()) return false;
        if (_isRange) {
            return (_lowerNum == portRangePair.getLowerNum() && _upperNum == portRangePair.getUpperNum());
        } else {
            return (_lowerNum == portRangePair.getLowerNum());
        }
    }
}

class Record {
    String      _direction;
    String      _protocol;
    PortRangePair _port;
    IPRangePair _ipAddress;

    public Record(String dir, String protocol, PortRangePair port, IPRangePair address) {
        _direction = new String(dir);
        _protocol  = new String(protocol);
        _port      = new PortRangePair(port);
        _ipAddress = new IPRangePair(address);
    }

    public PortRangePair getPort() {
        return _port;
    }

    public IPRangePair getIpAddress() {
        return _ipAddress;
    }

    int genHashKey(int idx) {
        switch(idx) {
            case 0:
                return _direction.hashCode() + _protocol.hashCode() + _port.hashCode() + _ipAddress.hashCode();
            case 1:
                return _direction.hashCode() + _protocol.hashCode() + _port.hashCode();
            case 2:
                return _direction.hashCode() + _protocol.hashCode() + _ipAddress.hashCode();
            case 3:
                return _direction.hashCode() + _protocol.hashCode();
            default:
                return -1;
        }
    }

    public boolean covers(Record record) {
        if (!_direction.equals(record._direction)) return false;
        if (!_protocol.equals(record._protocol)) return false;
        if (!_port.covers(record.getPort().getLowerNum())) return false;
        return _ipAddress.covers(record.getIpAddress().getLowerAddress());
    }

    @Override
    public int hashCode() {
        return _direction.hashCode() + _protocol.hashCode() + _port.hashCode() + _ipAddress.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (this.getClass() != o.getClass()) return false;
        Record record = (Record) o;
        if (!_direction.equals(record._direction)) return false;
        if (!_protocol.equals(record._protocol)) return false;
        if (!_port.equals(record._port)) return false;
        return _ipAddress.equals(record._ipAddress);
    }
}

class RuleSet {
    List<Map<Integer, ArrayList<Record>>> _set;

    public RuleSet() {
        _set = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            Map<Integer, ArrayList<Record>> curSet = new HashMap<>();
            _set.add(curSet);
        }
    }

    public void addRule(Record record) {
        int setNo;
        if (!record.getPort().isRange() && !record.getIpAddress().isRange()) {
            setNo = 0;
        } else if (!record.getPort().isRange() && record.getIpAddress().isRange()) {
            setNo = 1;
        } else if (record.getPort().isRange() && !record.getIpAddress().isRange()) {
            setNo = 2;
        } else {
            setNo = 3;
        }
        int key = record.genHashKey(setNo);
        ArrayList<Record> rules;
        /* current assumption: there is no overlapping or containment of rules */
        Map<Integer, ArrayList<Record>> curSet = _set.get(setNo);
        if (curSet.containsKey(key)) {
            rules = curSet.get(key);
        } else {
            rules = new ArrayList<>();
            curSet.put(key, rules);
        }
        rules.add(record);
    }

    boolean inRule(Record record) {
        for (int i = 0; i < 4; i++) {
            int key = record.genHashKey(i);
            Map<Integer, ArrayList<Record>> curSet = _set.get(i);
            if (curSet.containsKey(key)) {
                ArrayList<Record> rules = curSet.get(key);
                for (int j = 0; j < rules.size(); j++) {
                    Record curRule = rules.get(j);
                    if (curRule.covers(record)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}