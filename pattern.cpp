#include "all.h"
#include "pattern.h"

namespace memory
{
	pattern::pattern(std::string_view ida_sig)
	{
		auto to_hex = [&](char c) -> std::optional<std::uint8_t>
		{
			// Convert to uppercase if needed
			if (c >= 'a' && c <= 'f')
				c -= 32;

			if (c >= '0' && c <= '9')
				return static_cast<std::uint8_t>(c - '0');
			else if (c >= 'A' && c <= 'F')
				return static_cast<std::uint8_t>(c - 'A' + 10);

			return std::nullopt;
		};

		for (std::size_t i = 0; i < ida_sig.size(); i++)
		{
			if (ida_sig[i] == ' ')
				continue;

			bool last = (i == ida_sig.size() - 1);
			if (ida_sig[i] != '?')
			{
				if (!last)
				{
					auto c1 = to_hex(ida_sig[i]);
					auto c2 = to_hex(ida_sig[i + 1]);

					if (c1 && c2)
					{
						m_bytes.emplace_back(static_cast<std::uint8_t>((*c1 * 0x10) + *c2));
					}
				}
			}
			else
			{
				m_bytes.push_back(std::nullopt);
			}
		}
	}

	pattern::pattern(const void* bytes, std::string_view mask)
	{
		for (std::size_t i = 0; i < mask.size(); i++)
		{
			if (mask[i] != '?')
				m_bytes.emplace_back(static_cast<const std::uint8_t*>(bytes)[i]);
			else
				m_bytes.push_back(std::nullopt);
		}
	}
}
