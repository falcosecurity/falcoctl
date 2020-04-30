package validate

import (
	"github.com/go-playground/validator/v10"
	logger "github.com/sirupsen/logrus"
)

func isLogrusLevel(fl validator.FieldLevel) bool {
	level := fl.Field().String()
	lvl, err := logger.ParseLevel(level)
	if err != nil {
		return false
	}
	logger.SetLevel(lvl)
	return true
}
