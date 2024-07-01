1. DNS UPDATE "sync":

   Restructure the "tdns-cli ddns sync" command to
   a) be an API call into tdnsd and let tdnsd take care of it all
   b) not query for the child data; tdnsd already knows that
   c) cache the name of the parent zone in the ZoneData struct;
      also cache the parent nameservers
   d) not query for the name of the parentzone or the parent
      nameservers if we already know

2. DNS NOTIFY "sync"
