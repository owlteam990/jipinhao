//! 极品号后缀匹配：判断地址尾部是否落在吉利字符集内

/// 默认吉利字符：6 / 8 / 9 / A
pub const DEFAULT_CHARSET: &str = "689A";

/// 匹配模式配置
#[derive(Clone, Debug)]
pub struct MatchConfig {
    /// 要求连续位数
    pub length: usize,
    /// 允许出现的字符集合（已去重，用于展示）
    pub charset: Vec<char>,
    /// ASCII 查表：charset 内字符为 true
    lookup: [bool; 256],
    /// 是否要求后缀每一位都相同（豹子号）
    pub same_char: bool,
}

impl MatchConfig {
    /// 构建匹配配置并校验参数合法性
    ///
    /// # Arguments
    /// * `length` - 连续位数，至少为 1
    /// * `charset` - 吉利字符，如 "689A"
    /// * `same_char` - true 时要求后缀全相同
    ///
    /// # Returns
    /// 合法配置；charset 为空或 length 为 0 时返回错误信息
    pub fn new(length: usize, charset: &str, same_char: bool) -> Result<Self, String> {
        if length == 0 {
            return Err("连续位数必须大于 0".to_string());
        }
        let mut chars: Vec<char> = charset.chars().collect();
        chars.sort_unstable();
        chars.dedup();
        if chars.is_empty() {
            return Err("吉利字符集不能为空".to_string());
        }

        let mut lookup = [false; 256];
        for &c in &chars {
            if !c.is_ascii() {
                return Err(format!("吉利字符必须是 ASCII: {}", c));
            }
            lookup[c as usize] = true;
        }

        Ok(Self {
            length,
            charset: chars,
            lookup,
            same_char,
        })
    }

    /// 判断地址是否命中极品号规则
    ///
    /// # Arguments
    /// * `address` - Base58 TRON 地址
    ///
    /// # Returns
    /// 命中返回 true
    pub fn matches(&self, address: &str) -> bool {
        let bytes = address.as_bytes();
        if bytes.len() < self.length {
            return false;
        }

        let suffix = &bytes[bytes.len() - self.length..];

        // 每一位都必须在吉利字符集内
        for &b in suffix {
            if !self.lookup[b as usize] {
                return false;
            }
        }

        // 豹子号：后缀必须全相同
        if self.same_char {
            let first = suffix[0];
            return suffix.iter().all(|&b| b == first);
        }

        true
    }

    /// 人可读的规则描述
    pub fn describe(&self) -> String {
        let set: String = self.charset.iter().collect();
        if self.same_char {
            format!("尾部连续 {} 位相同，且字符属于 {{{}}}", self.length, set)
        } else {
            format!("尾部连续 {} 位均属于 {{{}}}", self.length, set)
        }
    }

    /// 单次尝试命中概率（近似）
    pub fn hit_probability(&self) -> f64 {
        const BASE58: f64 = 58.0;
        if self.same_char {
            // 允许的豹子模式数 / 58^n
            (self.charset.len() as f64) / BASE58.powi(self.length as i32)
        } else {
            // (charset_len / 58)^n
            (self.charset.len() as f64 / BASE58).powi(self.length as i32)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_lucky_suffix() {
        let cfg = MatchConfig::new(7, "689A", false).unwrap();
        // 尾部 7 位：6689AA6 均在吉利集内
        assert!(cfg.matches("TXyzABCDEF6689AA6"));
        // 尾部含 B，不命中
        assert!(!cfg.matches("TXyzABCDEF6689AAB"));
    }

    #[test]
    fn matches_same_char_only() {
        let cfg = MatchConfig::new(7, "689A", true).unwrap();
        assert!(cfg.matches("TXyzABCDEFG6666666"));
        assert!(!cfg.matches("TXyzABCDEFG6689AA"));
    }
}
