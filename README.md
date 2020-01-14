
2a. I tried to make cases that tested each of the sets(explained in part b) that I identified. I made several cases that checked the boundaries for cases with IP address or port ranges and also cases with addresses or port within the ranges. However, I did notice that one of my test cases actually does not return the expected result, but I ran out of time before I could fully investigate the issue.

2b. My design was primarily concerned with how to store the rules in a way where I could quickly check if the input from accept_packet is accepted by the rules. My solution was to use HashMaps as searching in a HashMap is constant time.

I identified and created 4 sets that were possible due to potential ranges given for IP Addresses and ports. 1. direction, protocol, port, and IP address are fixed values 2. direction, protocol, port are fixed values, IP address is a range 3. direction, protocol, IP address are fixed values, port is a range 4. direction, protocol are fixed values, port and IP address are a range.

I created PortRangePair and IPRangePair classes to help with handling fixed values and range value inputs listed in the csv. I created the RuleSet class to store the rules from the csv and I also created the Record class in which all the fields of a rule or input of accept_packet make up a Record object.

I needed to create 4 sets as generating the hash key was different for each scenario. Hash keys are made up of fixed values's hashcodes; if I had a range value, the hash key would be made up of the hashcodes of the fixed values and then I would check to see if the port or IP address range of that rule I matched using the hash key "covers" the port or IP address of the input passed into accept_packet.

To address comparing IP addresses and checking within a range of IP addresses, I created a genAddressNumber method. Because each integer in the IP address was in the range 0 to 255, I would bit shift each of the integers by multiples of 8.

2c. I would have liked more time to figure out what the bug is and better organize the FireWall Constructor. Code can also be cleaned up and naming methods can be improved/kept consistent.

3. My ranking for the teams starting from most interested is platform, policy, data.