include $(THEOS)/makefiles/common.mk

ARCHS = arm64

TOOL_NAME = expose_kernel_task

expose_kernel_task_FILES = main.m kernel_memory.c slide.c tasks.c patchfinder.c kcall.c cache_offsets.c pac.c hsp4.c gadget.c
expose_kernel_task_FRAMEWORKS= IOKit
expose_kernel_task_CFLAGS = -fobjc-arc
expose_kernel_task_CODESIGN_FLAGS = -Sentitlements.xml

include $(THEOS_MAKE_PATH)/tool.mk
