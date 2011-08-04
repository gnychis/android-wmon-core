MC1322X := libmc1322x

# all off the common objects for each target
# a COBJ is made for EACH board and goes the obj_$(BOARD)_board directory
# board specific code is OK in these files
COBJS := tests.o put.o

# all of the target programs to build
TARGETS := econotag_coexisyst_firmware
#TARGETS := blink-red blink-green blink-blue blink-white blink-allio \
           uart1-loopback \
           u1u2-loopback \
           tmr tmr-ints \
           sleep \
           printf \
	   asm \
	   adc \
	   pwm \
           wdt \
	   xtal-trim

# these targets are built with space reserved for variables needed by ROM services
# this space is initialized with a rom call to rom_data_init
TARGETS_WITH_ROM_VARS := econotag_coexisyst_firmware
#TARGETS_WITH_ROM_VARS := nvm-read nvm-write romimg flasher \
                         rftest-rx rftest-tx \
                         autoack-rx autoack-tx \
	                 per

##################################################
# you shouldn't need to edit anything below here #
##################################################

# This Makefile includes the default rule at the top
# it needs to be included first
-include $(MC1322X)/Makefile.include

# this rule will become the default_goal if
# $(MC1322X)/Makefile.include doesn't exist it will try to update the
# submodule, check if $(MC1322X) exists, and if it does
# try make again
submodule: 
	git submodule update --init
	if [ ! -d $(MC1322X) ] ; then echo "*** cannot find MC1322X directory $(MC1322X)" ; exit 2; fi
	$(MAKE)

.PHONY: submodule






