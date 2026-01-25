package components

import "fyne.io/fyne/v2/widget"

// KeyedRadio wraps widget.RadioGroup but keeps a stable SelectedKey.
type KeyedRadio struct {
	Radio       *widget.RadioGroup
	SelectedKey string

	keys       []string
	keyByLabel map[string]string
	labelByKey map[string]string
}

// NewKeyedRadioGroup builds a radio group that displays translated labels
// while storing stable selection keys.
func NewKeyedRadioGroup(
	keys []string,
	labelFn func(key string) string,
	onChanged func(key string),
) *KeyedRadio {

	keyByLabel := make(map[string]string, len(keys))
	labelByKey := make(map[string]string, len(keys))
	labels := make([]string, 0, len(keys))

	for _, k := range keys {
		l := labelFn(k)
		labels = append(labels, l)
		keyByLabel[l] = k
		labelByKey[k] = l
	}

	kr := &KeyedRadio{
		keys:       keys,
		keyByLabel: keyByLabel,
		labelByKey: labelByKey,
	}

	kr.Radio = widget.NewRadioGroup(labels, func(selectedLabel string) {
		k := kr.keyByLabel[selectedLabel]
		kr.SelectedKey = k
		if onChanged != nil {
			onChanged(k)
		}
	})

	return kr
}

// SetSelectedKey selects by stable key (not by label).
func (kr *KeyedRadio) SetSelectedKey(key string) {
	kr.SelectedKey = key
	if label, ok := kr.labelByKey[key]; ok {
		kr.Radio.SetSelected(label)
	}
}
