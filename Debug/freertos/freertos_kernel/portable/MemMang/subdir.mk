################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../freertos/freertos_kernel/portable/MemMang/heap_3.c 

C_DEPS += \
./freertos/freertos_kernel/portable/MemMang/heap_3.d 

OBJS += \
./freertos/freertos_kernel/portable/MemMang/heap_3.o 


# Each subdirectory must supply rules for building sources it contributes
freertos/freertos_kernel/portable/MemMang/%.o: ../freertos/freertos_kernel/portable/MemMang/%.c freertos/freertos_kernel/portable/MemMang/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MK64FN1M0VLL12 -DCPU_MK64FN1M0VLL12_cm4 -DUSE_RTOS=1 -DPRINTF_ADVANCED_ENABLE=1 -DFRDM_K64F -DFREEDOM -DLWIP_DISABLE_PBUF_POOL_SIZE_SANITY_CHECKS=1 -DSERIAL_PORT_TYPE_UART=1 -DSDK_OS_FREE_RTOS -DMCUXPRESSO_SDK -DSDK_DEBUGCONSOLE=1 -DCR_INTEGER_PRINTF -DPRINTF_FLOAT_ENABLE=0 -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\source" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\mdio" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\phy" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\lwip\contrib\apps\tcpecho" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\lwip\port" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\lwip\src" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\lwip\src\include" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\drivers" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\utilities" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\device" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\component\uart" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\component\serial_manager" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\component\lists" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\CMSIS" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\freertos\freertos_kernel\include" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\freertos\freertos_kernel\portable\GCC\ARM_CM4F" -I"C:\Users\frdmk64f_lwip_tcpecho_freertos_practica1\board" -O0 -fno-common -g3 -c -ffunction-sections -fdata-sections -ffreestanding -fno-builtin -fmerge-constants -fmacro-prefix-map="$(<D)/"= -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-freertos-2f-freertos_kernel-2f-portable-2f-MemMang

clean-freertos-2f-freertos_kernel-2f-portable-2f-MemMang:
	-$(RM) ./freertos/freertos_kernel/portable/MemMang/heap_3.d ./freertos/freertos_kernel/portable/MemMang/heap_3.o

.PHONY: clean-freertos-2f-freertos_kernel-2f-portable-2f-MemMang

