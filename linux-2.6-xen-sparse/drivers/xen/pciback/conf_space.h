/*
 * PCI Backend - Common data structures for overriding the configuration space
 *
 * Author: Ryan Wilson <hap9@epoch.ncsc.mil>
 */

#ifndef __XEN_PCIBACK_CONF_SPACE_H__
#define __XEN_PCIBACK_CONF_SPACE_H__

#include <linux/list.h>
#include <linux/err.h>

/* conf_field_init can return an errno in a ptr with ERR_PTR() */
typedef void *(*conf_field_init) (struct pci_dev * dev, int offset);
typedef void (*conf_field_reset) (struct pci_dev * dev, int offset, void *data);
typedef void (*conf_field_free) (struct pci_dev * dev, int offset, void *data);

typedef int (*conf_dword_write) (struct pci_dev * dev, int offset, u32 value,
				 void *data);
typedef int (*conf_word_write) (struct pci_dev * dev, int offset, u16 value,
				void *data);
typedef int (*conf_byte_write) (struct pci_dev * dev, int offset, u8 value,
				void *data);
typedef int (*conf_dword_read) (struct pci_dev * dev, int offset, u32 * value,
				void *data);
typedef int (*conf_word_read) (struct pci_dev * dev, int offset, u16 * value,
			       void *data);
typedef int (*conf_byte_read) (struct pci_dev * dev, int offset, u8 * value,
			       void *data);

/* These are the fields within the configuration space which we
 * are interested in intercepting reads/writes to and changing their
 * values.
 */
struct config_field {
	unsigned int     offset;
	unsigned int     size;
	conf_field_init  init;
	conf_field_reset reset;
	conf_field_free  release;
	union {
		struct {
			conf_dword_write write;
			conf_dword_read read;
		} dw;
		struct {
			conf_word_write write;
			conf_word_read read;
		} w;
		struct {
			conf_byte_write write;
			conf_byte_read read;
		} b;
	} u;
};

struct config_field_entry {
	struct list_head list;
	struct config_field *field;
	unsigned int base_offset;
	void *data;
};

#define OFFSET(cfg_entry) ((cfg_entry)->base_offset+(cfg_entry)->field->offset)

/* Add fields to a device - the add_fields macro expects to get a pointer to
 * the first entry in an array (of which the ending is marked by size==0)
 */
int pciback_config_add_field_offset(struct pci_dev *dev,
				    struct config_field *field,
				    unsigned int offset);

static inline int pciback_config_add_field(struct pci_dev *dev,
					   struct config_field *field)
{
	return pciback_config_add_field_offset(dev, field, 0);
}

static inline int pciback_config_add_fields(struct pci_dev *dev,
					    struct config_field *field)
{
	int i, err = 0;
	for (i = 0; field[i].size != 0; i++) {
		err = pciback_config_add_field(dev, &field[i]);
		if (err)
			break;
	}
	return err;
}

static inline int pciback_config_add_fields_offset(struct pci_dev *dev,
						   struct config_field *field,
						   unsigned int offset)
{
	int i, err = 0;
	for (i = 0; field[i].size != 0; i++) {
		err = pciback_config_add_field_offset(dev, &field[i], offset);
		if (err)
			break;
	}
	return err;
}

/* Read/Write the real configuration space */
int pciback_read_config_byte(struct pci_dev *dev, int offset, u8 * value,
			     void *data);
int pciback_read_config_word(struct pci_dev *dev, int offset, u16 * value,
			     void *data);
int pciback_read_config_dword(struct pci_dev *dev, int offset, u32 * value,
			      void *data);
int pciback_write_config_byte(struct pci_dev *dev, int offset, u8 value,
			      void *data);
int pciback_write_config_word(struct pci_dev *dev, int offset, u16 value,
			      void *data);
int pciback_write_config_dword(struct pci_dev *dev, int offset, u32 value,
			       void *data);

int pciback_config_capability_init(void);

int pciback_config_header_add_fields(struct pci_dev *dev);
int pciback_config_capability_add_fields(struct pci_dev *dev);

#endif				/* __XEN_PCIBACK_CONF_SPACE_H__ */
