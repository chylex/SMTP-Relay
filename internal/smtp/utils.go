package smtp

import (
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func containsKey[K comparable, V any](m map[K]V, key K) bool {
	_, ok := m[key]
	return ok
}

func generateUUID(log *logrus.Logger) string {
	id, err := uuid.NewRandom()
	if err != nil {
		log.WithError(err).Error("could not generate UUIDv4")
		return ""
	} else {
		return id.String()
	}
}
