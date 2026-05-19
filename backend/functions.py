class Solution(object):
    def longestPalindrome(self, s):
        """
        :type s: str
        :rtype: str
        """
        res = ""
        
        for i in range(len(s)):
            # odd length
            temp = self.expand(s, i, i)
            if len(temp) > len(res):
                res = temp
            
            # even length
            temp = self.expand(s, i, i+1)
            if len(temp) > len(res):
                res = temp
                
        return res
    
    def expand(self, s, left, right):
        while left >= 0 and right < len(s) and s[left] == s[right]:
            left -= 1
            right += 1
        return s[left+1:right]
s = Solution()
r = s.longestPalindrome('babad')
print(r)