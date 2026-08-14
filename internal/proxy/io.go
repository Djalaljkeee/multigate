package proxy

import "io"

// maxBodyBytes - жёсткий потолок на тело ответа апстрима. Настоящая
// подписка весит десятки-сотни килобайт, а несколько мегабайт уже аномалия
// (например, панель отдала что-то не то), от которой прослойку и клиента
// стоит защитить, а не пытаться дочитать до конца.
const maxBodyBytes = 8 << 20 // 8 МБ

// readLimited читает тело ответа с ограничением по размеру.
func readLimited(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxBodyBytes))
}
