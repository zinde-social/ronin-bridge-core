package models

import (
	"gorm.io/gorm"
)

type ProcessedBlock struct {
	ChainId string `json:"chainId" gorm:"primary_key:true;column:chain_id;"`
	Block   int64  `json:"block" gorm:"column:block;not null"`
}

func (m ProcessedBlock) BeforeCreate(tx *gorm.DB) (err error) {
	return nil
}

func (m ProcessedBlock) TableName() string {
	return "processed_block"
}
