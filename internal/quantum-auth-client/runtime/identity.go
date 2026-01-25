package runtime

type Identity struct {
	UserID   string
	DeviceID string
}

func (id Identity) IsZero() bool {
	return id.UserID == "" || id.DeviceID == ""
}
