Analysis
========

The following commands were used to prepare the raw symbol data for analysis:

    cut -d, -f 7 all_symbols.csv | sort | uniq > unique_symbols.txt

    clear && make hashgen && ./hashgen unique_symbols.txt > unique_symbols_with_gnu_hash.csv

    cut -d, -f2 unique_symbols_with_gnu_hash.csv | sort > sorted_hashes

    $ uniq -c sorted_hashes | grep -v "      1 "
         2 b885e2d
         2 d69f1ed795ee98d0
         2 d69f21667ee77ad2
         2 d69f22adf363ebd3
         2 d69f253cdc5ccdd5

So, we identified 5 collisions with the gnu_hash algorithm... the collisions 
look like this:
      
    $ grep b885e2d unique_symbols_with_gnu_hash.csv 
    any,b885e2d
    c.7,b885e2d
    
    $ grep d69f1ed795ee98d0 unique_symbols_with_gnu_hash.csv 
    type.._62x_7uint8,d69f1ed795ee98d0
    type.._646_7uint8,d69f1ed795ee98d0
    
    $ grep d69f21667ee77ad2 unique_symbols_with_gnu_hash.csv 
    type.._64x_7uint8,d69f21667ee77ad2
    type.._666_7uint8,d69f21667ee77ad2
    
    $ grep d69f22adf363ebd3 unique_symbols_with_gnu_hash.csv 
    type.._65x_7uint8,d69f22adf363ebd3
    type.._676_7uint8,d69f22adf363ebd3
    
    $ grep d69f253cdc5ccdd5 unique_symbols_with_gnu_hash.csv 
    type.._67x_7uint8,d69f253cdc5ccdd5
    type.._696_7uint8,d69f253cdc5ccdd5


      